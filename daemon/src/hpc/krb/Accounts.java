package hpc.krb;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * HPC account lookups (getent passwd) and the UID -> AD principal map.
 *
 * uidmap.conf, one entry per line:   <username-or-uid>   <sAMAccountName or principal>
 * The file must be root-owned and not group/world writable; it is re-read
 * when its mtime changes, so enrollment needs no daemon restart.
 */
final class Accounts {
    record User(String name, int uid, int gid, String home) {}

    private final Path mapFile;
    private final String realm;
    private volatile long mtime = -1;
    private volatile Map<String, String> byName = Map.of();
    private final Map<String, User> pwCache = new ConcurrentHashMap<>();

    Accounts(Path mapFile, String realm) {
        this.mapFile = mapFile;
        this.realm = realm;
    }

    /** Principal for an HPC user, or empty if the user is not enrolled. */
    Optional<String> principal(User u) throws IOException {
        reload();
        String p = byName.get(u.name());
        if (p == null) p = byName.get(Integer.toString(u.uid()));
        if (p == null) return Optional.empty();
        return Optional.of(p.contains("@") ? p : p + "@" + realm);
    }

    Optional<User> lookup(String nameOrUid) throws IOException {
        User cached = pwCache.get(nameOrUid);
        if (cached != null) return Optional.of(cached);
        Process pr = new ProcessBuilder("getent", "passwd", nameOrUid).redirectErrorStream(true).start();
        String line = new String(pr.getInputStream().readAllBytes(), StandardCharsets.UTF_8).trim();
        try {
            if (pr.waitFor() != 0 || line.isEmpty()) return Optional.empty();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return Optional.empty();
        }
        String[] f = line.split(":", -1);
        User u = new User(f[0], Integer.parseInt(f[2]), Integer.parseInt(f[3]), f[5]);
        pwCache.put(nameOrUid, u);
        return Optional.of(u);
    }

    private synchronized void reload() throws IOException {
        long m = Files.getLastModifiedTime(mapFile).toMillis();
        if (m == mtime) return;
        int owner = (Integer) Files.getAttribute(mapFile, "unix:uid", LinkOption.NOFOLLOW_LINKS);
        Set<PosixFilePermission> perms = Files.getPosixFilePermissions(mapFile);
        if (owner != 0 || perms.contains(PosixFilePermission.GROUP_WRITE) || perms.contains(PosixFilePermission.OTHERS_WRITE)) {
            throw new IOException(mapFile + " must be root-owned and not group/world writable");
        }
        Map<String, String> m2 = new HashMap<>();
        for (String ln : Files.readAllLines(mapFile)) {
            int hash = ln.indexOf('#');
            if (hash >= 0) ln = ln.substring(0, hash);
            String[] f = ln.trim().split("\\s+");
            if (f.length >= 2) m2.put(f[0], f[1]);
        }
        byName = Map.copyOf(m2);
        mtime = m;
        Log.info("uid map loaded: %d entries", m2.size());
    }
}
