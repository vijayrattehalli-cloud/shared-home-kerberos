package hpc.krb;

import java.io.IOException;
import java.io.Reader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Properties;

/** credd.properties -- see solution-b-java24/config/credd.properties for documentation. */
public record Config(
        String realm,
        Path keytabDir,
        Path uidMap,
        Path socket,
        String ccacheTemplate,      // e.g. {home}/.krb5/krb5cc_hpc
        Path installHelper,         // common/bin/krb-install-ccache
        String setpriv,
        Duration refreshInterval,
        Duration renewMargin,
        Duration activeWindow,      // keep users fresh this long after their last request
        boolean watchSlurm,         // keep tickets fresh for users with pending/running jobs
        String squeue,
        Path krb5Conf) {

    public static Config load(Path p) throws IOException {
        Properties pr = new Properties();
        try (Reader r = Files.newBufferedReader(p)) {
            pr.load(r);
        }
        return new Config(
                req(pr, "realm"),
                Path.of(pr.getProperty("keytab_dir", "/etc/krb-hpc/keytabs")),
                Path.of(pr.getProperty("uid_map", "/etc/krb-hpc/uidmap.conf")),
                Path.of(pr.getProperty("socket", "/run/krb-hpc/credd.sock")),
                pr.getProperty("ccache_path", "{home}/.krb5/krb5cc_hpc"),
                Path.of(pr.getProperty("install_helper", "/usr/local/libexec/krb-hpc/krb-install-ccache")),
                pr.getProperty("setpriv", "/usr/bin/setpriv"),
                dur(pr.getProperty("refresh_interval", "5m")),
                dur(pr.getProperty("renew_margin", "2h")),
                dur(pr.getProperty("active_window", "7d")),
                Boolean.parseBoolean(pr.getProperty("watch_slurm", "true")),
                pr.getProperty("squeue", "/usr/bin/squeue"),
                Path.of(pr.getProperty("krb5_conf", "/etc/krb5.conf")));
    }

    private static String req(Properties p, String k) {
        String v = p.getProperty(k);
        if (v == null || v.isBlank()) throw new IllegalArgumentException("missing config key " + k);
        return v.trim();
    }

    static Duration dur(String s) {
        s = s.trim();
        char u = s.charAt(s.length() - 1);
        long n = Long.parseLong(Character.isDigit(u) ? s : s.substring(0, s.length() - 1));
        return switch (u) {
            case 'd' -> Duration.ofDays(n);
            case 'h' -> Duration.ofHours(n);
            case 'm' -> Duration.ofMinutes(n);
            default -> Duration.ofSeconds(n);
        };
    }
}
