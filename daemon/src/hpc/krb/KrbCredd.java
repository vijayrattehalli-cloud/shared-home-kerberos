package hpc.krb;

import java.io.IOException;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import jdk.net.ExtendedSocketOptions;
import jdk.net.UnixDomainPrincipal;

/**
 * krb-credd (Java 24 edition) -- Kerberos credential daemon for a UID/GID HPC.
 *
 * Users authenticate to the HPC with their CAC; the CAC cannot be used via
 * GSSAPI/PKINIT, so this root daemon obtains each enrolled user's AD TGT
 * from an escrowed keytab and writes it to the user's home directory
 * ({home}/.krb5/krb5cc_hpc by default). Because home directories are on the
 * cluster's shared filesystem, every compute node of every Slurm job sees the
 * same, continuously refreshed ticket -- no per-node forwarding agent needed.
 *
 * Triggers:
 *   - UNIX socket request from a logged-in user (identity from SO_PEERCRED)
 *   - periodic pass for recently-active users and for every user that has a
 *     pending/running Slurm job (squeue), so tickets never expire mid-job and
 *     jobs longer than the renew limit get a fresh TGT from the keytab.
 *
 * Java 24 notes: no SecurityManager (JEP 486) is used or needed; the UNIX
 * socket + SO_PEERCRED come from java.net / jdk.net; connections are handled
 * on virtual threads.
 *
 *   java -Djava.security.krb5.conf=/etc/krb5.conf -jar krb-credd.jar /etc/krb-hpc/credd.properties
 */
public final class KrbCredd {

    public static void main(String[] args) throws Exception {
        Path conf = Path.of(args.length > 0 ? args[0] : "/etc/krb-hpc/credd.properties");
        Config cfg = Config.load(conf);
        System.setProperty("java.security.krb5.conf", cfg.krb5Conf().toString());
        System.setProperty("sun.security.krb5.disableReferrals", "false");

        Accounts accounts = new Accounts(cfg.uidMap(), cfg.realm());
        TicketManager tm = new TicketManager(cfg, accounts);

        ScheduledExecutorService sched = Executors.newSingleThreadScheduledExecutor();
        long every = cfg.refreshInterval().toSeconds();
        sched.scheduleWithFixedDelay(tm::refreshPass, every, every, TimeUnit.SECONDS);

        Files.createDirectories(cfg.socket().getParent());
        Files.deleteIfExists(cfg.socket());
        try (ServerSocketChannel server = ServerSocketChannel.open(StandardProtocolFamily.UNIX)) {
            server.bind(UnixDomainSocketAddress.of(cfg.socket()));
            // anyone may connect; the kernel-supplied peer identity decides whose ticket is issued
            Files.setPosixFilePermissions(cfg.socket(), PosixFilePermissions.fromString("rw-rw-rw-"));
            Log.info("listening on %s (refresh every %ds, slurm watch=%s)", cfg.socket(), every, cfg.watchSlurm());
            try (var pool = Executors.newVirtualThreadPerTaskExecutor()) {
                while (true) {
                    SocketChannel ch = server.accept();
                    pool.submit(() -> handle(ch, accounts, tm));
                }
            }
        }
    }

    private static void handle(SocketChannel ch, Accounts accounts, TicketManager tm) {
        try (ch) {
            UnixDomainPrincipal peer = ch.getOption(ExtendedSocketOptions.SO_PEERCRED);
            String who = peer.user().getName();
            String req = readLine(ch);
            if (!"GET".equals(req)) {
                reply(ch, "ERR unsupported request");
                return;
            }
            var user = accounts.lookup(who);
            if (user.isEmpty()) {
                reply(ch, "ERR unknown user");
                return;
            }
            try {
                Path p = tm.ensure(user.get(), true);
                tm.markActive(user.get());
                reply(ch, "OK " + p);
                Log.info("issued TGT to %s -> %s", who, p);
            } catch (SecurityException e) {
                reply(ch, "ERR " + e.getMessage());
                Log.warn("denied %s: %s", who, e.getMessage());
            } catch (Exception e) {
                reply(ch, "ERR could not obtain ticket");
                Log.error("failed for %s: %s", who, e);
            }
        } catch (IOException e) {
            Log.warn("connection error: %s", e.getMessage());
        }
    }

    static String readLine(SocketChannel ch) throws IOException {
        ByteBuffer b = ByteBuffer.allocate(256);
        while (b.hasRemaining()) {
            if (ch.read(b) < 0) break;
            byte[] a = b.array();
            for (int i = 0; i < b.position(); i++) {
                if (a[i] == '\n') return new String(a, 0, i, StandardCharsets.US_ASCII).trim();
            }
        }
        return new String(b.array(), 0, b.position(), StandardCharsets.US_ASCII).trim();
    }

    static void reply(SocketChannel ch, String s) throws IOException {
        ch.write(ByteBuffer.wrap((s + "\n").getBytes(StandardCharsets.UTF_8)));
    }
}
