package hpc.krb;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.Statement;
import java.util.Map;
import java.util.concurrent.CompletionException;
import javax.security.auth.Subject;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;

/**
 * Hive JDBC over Kerberos on JDK 24.
 *
 * - Logs in from the FILE: ccache that krb-credd keeps in $HOME (KRB5CCNAME);
 *   no keytab or password in the job.
 * - Uses Subject.callAs (Subject.doAs/getSubject are deprecated for removal
 *   and getSubject always throws on JDK 24).
 * - Requires kerberosAuthType=fromSubject, binary transport, and the
 *   hive-jdbc-jdk24-shim.jar ahead of the driver on the classpath.
 *
 *   java -cp hive-jdbc-jdk24-shim.jar:hive-jdbc-4.0.1-standalone.jar:hpc-hive-krb24.jar \
 *        hpc.krb.HiveKerberosClient24 "<jdbc url>" "<sql>"
 */
public final class HiveKerberosClient24 {

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.err.println("usage: HiveKerberosClient24 <jdbc-url> <sql>");
            System.exit(2);
        }
        String url = args[0];
        String sql = args[1];
        if (!url.contains("kerberosAuthType=fromSubject")) {
            System.err.println("warning: add ;kerberosAuthType=fromSubject -- the driver's other Kerberos path "
                    + "goes through Hadoop UserGroupInformation, which fails on JDK 24 unless the driver bundles Hadoop >= 3.4.3");
        }
        if (url.contains("transportMode=http")) {
            System.err.println("warning: HTTP transport + fromSubject calls Subject.getSubject in HiveConnection itself; "
                    + "the shim only fixes binary transport on JDK 24");
        }
        requireShim();

        Subject subject = loginFromTicketCache();
        System.err.println("Kerberos principal: " + subject.getPrincipals().iterator().next());

        try {
            Subject.callAs(subject, () -> {
                try (Connection c = DriverManager.getConnection(url);
                     Statement st = c.createStatement();
                     ResultSet rs = st.executeQuery(sql)) {
                    print(rs);
                }
                return null;
            });
        } catch (CompletionException e) {
            throw (e.getCause() instanceof Exception ex) ? ex : e;
        }
    }

    /** JAAS login that only reads the existing ccache: never prompts, never renews (krb-credd owns renewal). */
    public static Subject loginFromTicketCache() throws Exception {
        String cc = System.getenv("KRB5CCNAME");
        if (cc == null || cc.isBlank()) {
            cc = "FILE:" + System.getProperty("user.home") + "/.krb5/krb5cc_hpc";
        }
        if (cc.startsWith("KEYRING:") || cc.startsWith("KCM:") || cc.startsWith("API:") || cc.startsWith("DIR:")) {
            throw new IllegalStateException("Java can only read FILE: ccaches, got " + cc);
        }
        String path = cc.startsWith("FILE:") ? cc.substring(5) : cc;
        if (!Files.isReadable(Path.of(path))) {
            throw new IllegalStateException("no ticket cache at " + path + " -- run `eval $(krb-get)` on a login node");
        }
        Map<String, String> opts = Map.of(
                "useTicketCache", "true",
                "ticketCache", path,
                "renewTGT", "false",
                "doNotPrompt", "true",
                "useKeyTab", "false",
                "storeKey", "false",
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
        LoginContext lc = new LoginContext("HiveClient", new Subject(), null, jaas);
        lc.login();
        return lc.getSubject();
    }

    private static void requireShim() {
        try {
            Class.forName("org.apache.hive.service.auth.TSubjectAssumingTransport")
                    .getField("KRB_HPC_JDK24_SHIM");
        } catch (ClassNotFoundException e) {
            throw new IllegalStateException("Hive JDBC driver not on classpath", e);
        } catch (NoSuchFieldException e) {
            throw new IllegalStateException(
                    "hive-jdbc-jdk24-shim.jar must come BEFORE the Hive driver jar on the classpath", e);
        }
    }

    private static void print(ResultSet rs) throws Exception {
        ResultSetMetaData md = rs.getMetaData();
        int n = md.getColumnCount();
        StringBuilder h = new StringBuilder();
        for (int i = 1; i <= n; i++) h.append(i > 1 ? "\t" : "").append(md.getColumnLabel(i));
        System.out.println(h);
        while (rs.next()) {
            StringBuilder r = new StringBuilder();
            for (int i = 1; i <= n; i++) r.append(i > 1 ? "\t" : "").append(rs.getString(i));
            System.out.println(r);
        }
    }
}
