package hpc.krb;

import java.time.Instant;

/** Minimal stderr logger (journald adds its own timestamps; ours help when run by hand). */
final class Log {
    private Log() {}

    static void info(String fmt, Object... a) { emit("INFO", fmt, a); }
    static void warn(String fmt, Object... a) { emit("WARN", fmt, a); }
    static void error(String fmt, Object... a) { emit("ERROR", fmt, a); }

    private static void emit(String lvl, String fmt, Object... a) {
        System.err.println(Instant.now() + " krb-credd " + lvl + " " + String.format(fmt, a));
    }
}
