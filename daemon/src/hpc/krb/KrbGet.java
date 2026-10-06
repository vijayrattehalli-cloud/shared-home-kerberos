package hpc.krb;

import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;

/**
 * krb-get: ask krb-credd to refresh your TGT in your home directory.
 *
 *   eval "$(krb-get)"     ->  export KRB5CCNAME=FILE:/home/jdoe/.krb5/krb5cc_hpc
 */
public final class KrbGet {
    public static void main(String[] args) throws Exception {
        Path sock = Path.of(System.getenv().getOrDefault("KRB_HPC_SOCKET", "/run/krb-hpc/credd.sock"));
        try (SocketChannel ch = SocketChannel.open(StandardProtocolFamily.UNIX)) {
            ch.connect(UnixDomainSocketAddress.of(sock));
            ch.write(ByteBuffer.wrap("GET\n".getBytes(StandardCharsets.US_ASCII)));
            String resp = KrbCredd.readLine(ch);
            if (resp.startsWith("OK ")) {
                System.out.println("export KRB5CCNAME=FILE:" + resp.substring(3));
            } else {
                System.err.println("krb-get: " + resp.replaceFirst("^ERR ", ""));
                System.exit(1);
            }
        }
    }
}
