package hpc.krb;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;
import javax.security.auth.RefreshFailedException;
import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosTicket;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

/**
 * Acquires, renews and installs TGTs using only public JDK 24 APIs:
 *   - acquire:  JAAS Krb5LoginModule with the user's escrowed AD keytab
 *   - renew:    KerberosTicket.refresh()  (TGS renewal until renew-till)
 *   - install:  CCacheWriter -> MIT FILE: ccache -> written AS THE USER into
 *               their home directory through setpriv + krb-install-ccache,
 *               so it works on root-squashed NFS/GPFS/Lustre homes.
 */
final class TicketManager {
    private record Held(KerberosTicket tgt, Instant installed) {}

    private final Config cfg;
    private final Accounts accounts;
    private final Map<Integer, Held> held = new ConcurrentHashMap<>();
    private final Map<Integer, ReentrantLock> locks = new ConcurrentHashMap<>();
    private final Map<Integer, Instant> lastRequest = new ConcurrentHashMap<>();

    TicketManager(Config cfg, Accounts accounts) {
        this.cfg = cfg;
        this.accounts = accounts;
    }

    /** Ensure a fresh TGT exists for this user and is installed in their home. Returns the ccache path. */
    Path ensure(Accounts.User u, boolean forceInstall) throws Exception {
        String principal = accounts.principal(u)
                .orElseThrow(() -> new SecurityException("user " + u.name() + " is not enrolled"));
        ReentrantLock lock = locks.computeIfAbsent(u.uid(), k -> new ReentrantLock());
        lock.lock();
        try {
            Held h = held.get(u.uid());
            KerberosTicket t = h == null ? null : h.tgt();
            boolean changed = false;
            Instant now = Instant.now();

            if (t != null && remaining(t, now).compareTo(cfg.renewMargin()) < 0) {
                if (t.isRenewable() && t.getRenewTill() != null
                        && Duration.between(now, t.getRenewTill().toInstant()).compareTo(cfg.renewMargin()) > 0) {
                    try {
                        t.refresh();
                        changed = true;
                        Log.info("renewed TGT user=%s until %s", u.name(), t.getEndTime().toInstant());
                    } catch (RefreshFailedException e) {
                        Log.warn("renew failed user=%s: %s", u.name(), e.getMessage());
                        t = null;
                    }
                } else {
                    t = null; // past renew-till: re-acquire from keytab
                }
            }
            if (t == null) {
                t = acquire(principal);
                changed = true;
                Log.info("acquired TGT user=%s principal=%s flags=%s", u.name(), principal, flagString(t));
            }

            Path dest = ccachePath(u);
            if (changed || forceInstall || h == null) {
                install(u, dest, CCacheWriter.toFileCCache(t));
                held.put(u.uid(), new Held(t, now));
            }
            return dest;
        } finally {
            lock.unlock();
        }
    }

    void markActive(Accounts.User u) {
        lastRequest.put(u.uid(), Instant.now());
    }

    /** Periodic pass: keep tickets fresh for recently-active users and users with Slurm jobs. */
    void refreshPass() {
        Instant horizon = Instant.now().minus(cfg.activeWindow());
        lastRequest.entrySet().removeIf(e -> {
            if (e.getValue().isBefore(horizon)) {
                Held h = held.remove(e.getKey());
                if (h != null) quietDestroy(h.tgt());
                return true;
            }
            return false;
        });
        java.util.Set<String> users = new java.util.TreeSet<>();
        for (Integer uid : lastRequest.keySet()) users.add(uid.toString());
        if (cfg.watchSlurm()) users.addAll(slurmUsers());
        for (String who : users) {
            try {
                var u = accounts.lookup(who);
                if (u.isPresent() && accounts.principal(u.get()).isPresent()) ensure(u.get(), false);
            } catch (Exception e) {
                Log.error("refresh %s: %s", who, e);
            }
        }
    }

    // ------------------------------------------------------------------

    private KerberosTicket acquire(String principal) throws LoginException, IOException {
        Path kt = cfg.keytabDir().resolve(principal.substring(0, principal.indexOf('@')).replace('/', '_') + ".keytab");
        if (!Files.isReadable(kt)) throw new IOException("no escrowed keytab " + kt);
        Map<String, String> opts = Map.of(
                "useKeyTab", "true",
                "keyTab", kt.toString(),
                "principal", principal,
                "storeKey", "false",
                "doNotPrompt", "true",
                "useTicketCache", "false",
                "isInitiator", "true",
                "refreshKrb5Config", "true");
        Configuration jaas = new Configuration() {
            @Override
            public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
                return new AppConfigurationEntry[] {new AppConfigurationEntry(
                        "com.sun.security.auth.module.Krb5LoginModule",
                        AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, opts)};
            }
        };
        LoginContext lc = new LoginContext("krb-credd", new Subject(), null, jaas);
        lc.login();
        for (KerberosTicket t : lc.getSubject().getPrivateCredentials(KerberosTicket.class)) {
            if (t.getServer().getName().startsWith("krbtgt/")) return t;
        }
        throw new LoginException("login succeeded but no TGT in Subject");
    }

    Path ccachePath(Accounts.User u) {
        return Path.of(cfg.ccacheTemplate()
                .replace("{home}", u.home())
                .replace("{uid}", Integer.toString(u.uid()))
                .replace("{user}", u.name()));
    }

    /** Write the ccache as the user (setpriv drops root), atomically, mode 0600 in a 0700 dir. */
    private void install(Accounts.User u, Path dest, byte[] ccache) throws IOException, InterruptedException {
        List<String> cmd = List.of(cfg.setpriv(),
                "--reuid=" + u.uid(), "--regid=" + u.gid(), "--init-groups",
                "--inh-caps=-all", "--bounding-set=-all",
                cfg.installHelper().toString(), dest.toString());
        Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
        try (OutputStream os = p.getOutputStream()) {
            os.write(ccache);
        }
        if (!p.waitFor(30, TimeUnit.SECONDS)) {
            p.destroyForcibly();
            throw new IOException("install helper timed out");
        }
        String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8).trim();
        if (p.exitValue() != 0) throw new IOException("install helper failed: " + out);
    }

    private java.util.Set<String> slurmUsers() {
        java.util.Set<String> s = new java.util.TreeSet<>();
        try {
            // uids of users with pending, configuring, running or completing jobs
            Process p = new ProcessBuilder(cfg.squeue(), "-h", "-a", "-t", "PD,CF,R,CG", "-o", "%U")
                    .redirectErrorStream(true).start();
            for (String ln : new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8).split("\\R")) {
                if (ln.strip().matches("\\d+")) s.add(ln.strip());
            }
            p.waitFor(30, TimeUnit.SECONDS);
        } catch (Exception e) {
            Log.warn("squeue failed: %s", e.getMessage());
        }
        return s;
    }

    private static Duration remaining(KerberosTicket t, Instant now) {
        return Duration.between(now, t.getEndTime().toInstant());
    }

    static String flagString(KerberosTicket t) {
        return (t.isForwardable() ? "F" : "") + (t.isRenewable() ? "R" : "") + (t.isInitial() ? "I" : "");
    }

    private static void quietDestroy(KerberosTicket t) {
        try {
            t.destroy();
        } catch (Exception ignored) {
        }
    }
}
