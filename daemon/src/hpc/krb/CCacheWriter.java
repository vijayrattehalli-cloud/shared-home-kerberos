package hpc.krb;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.kerberos.KerberosTicket;

/**
 * Serialises a {@link KerberosTicket} into an MIT "FILE:" credential cache
 * (format version 0x0504), using only public JDK APIs.
 *
 * The JDK can read FILE: caches but has no public API to write them. Writing
 * the documented MIT format directly avoids --add-exports into
 * sun.security.krb5.*, so the daemon keeps working across JDK updates. The
 * output is readable by MIT/Heimdal klist, kvno, curl, ssh, python-gssapi and
 * by the JDK's own Krb5LoginModule (useTicketCache=true).
 *
 * Format reference: MIT krb5 "ccache_file_format" (doc/formats/ccache_file_format.rst).
 */
public final class CCacheWriter {
    private CCacheWriter() {}

    public static byte[] toFileCCache(KerberosTicket t) throws IOException {
        ByteArrayOutputStream bo = new ByteArrayOutputStream(4096);
        DataOutputStream o = new DataOutputStream(bo); // big-endian, as v4 requires

        o.writeShort(0x0504);
        // header: one tag (1 = KDC time offset), 8 bytes of zero
        o.writeShort(12);
        o.writeShort(1);
        o.writeShort(8);
        o.writeInt(0);
        o.writeInt(0);

        principal(o, t.getClient()); // default principal

        // --- one credential: the TGT ---
        principal(o, t.getClient());
        principal(o, t.getServer());
        o.writeShort(t.getSessionKeyType());
        counted(o, t.getSessionKey().getEncoded());

        Date auth = t.getAuthTime() != null ? t.getAuthTime() : t.getStartTime();
        o.writeInt(secs(auth));
        o.writeInt(secs(t.getStartTime() != null ? t.getStartTime() : auth));
        o.writeInt(secs(t.getEndTime()));
        o.writeInt(t.getRenewTill() == null ? 0 : secs(t.getRenewTill()));
        o.writeByte(0);                    // is_skey
        o.writeInt(flags(t.getFlags()));

        InetAddress[] addrs = t.getClientAddresses();
        if (addrs == null) {
            o.writeInt(0);
        } else {
            o.writeInt(addrs.length);
            for (InetAddress a : addrs) {
                o.writeShort(a instanceof Inet4Address ? 2 : 24); // ADDRTYPE_INET / INET6
                counted(o, a.getAddress());
            }
        }
        o.writeInt(0);                      // authdata count
        counted(o, t.getEncoded());         // ASN.1 DER Ticket
        counted(o, new byte[0]);            // second_ticket
        o.flush();
        return bo.toByteArray();
    }

    /** MIT stores RFC 4120 flag bit n (0 = most significant) as 1 << (31 - n). */
    static int flags(boolean[] f) {
        int v = 0;
        if (f != null) {
            for (int i = 0; i < f.length && i < 32; i++) {
                if (f[i]) v |= 1 << (31 - i);
            }
        }
        return v;
    }

    private static void principal(DataOutputStream o, KerberosPrincipal p) throws IOException {
        String full = p.getName();
        String realm = p.getRealm();
        String name = full.endsWith("@" + realm) ? full.substring(0, full.length() - realm.length() - 1) : full;
        String[] comps = name.split("/", -1);
        o.writeInt(p.getNameType());
        o.writeInt(comps.length);
        counted(o, realm.getBytes(StandardCharsets.UTF_8));
        for (String c : comps) counted(o, c.getBytes(StandardCharsets.UTF_8));
    }

    private static void counted(DataOutputStream o, byte[] b) throws IOException {
        o.writeInt(b.length);
        o.write(b);
    }

    private static int secs(Date d) {
        return d == null ? 0 : (int) (d.getTime() / 1000L); // unsigned 32-bit on disk
    }
}
