/*
 * LakeFSKerberosCredentialProvider -- an S3A AWSCredentialsProvider that trades
 * the job's Kerberos ticket (SPNEGO) at the lakeFS credential broker for a
 * SHORT-LIVED lakeFS access key, then feeds that key to S3A (SigV4).
 *
 * Runs on every Spark executor. It reads the Kerberos credentials from the
 * ambient native ccache (KRB5CCNAME -- the krb-credd shared-home cache), which
 * holds ONLY the pre-minted HTTP/<host> service ticket (no TGT). For that to
 * work the JVM must delegate GSSAPI to the OS (MIT) library:
 *
 *     --conf spark.executor.extraJavaOptions=-Dsun.security.jgss.native=true
 *     --conf spark.driver.extraJavaOptions=-Dsun.security.jgss.native=true
 *
 * S3A wiring (see spark-s3a.conf.example):
 *     fs.s3a.aws.credentials.provider = com.example.lakefs.LakeFSKerberosCredentialProvider
 *     fs.s3a.ext.lakefs.broker.url    = https://lakefs-sts.corp.example.mil/credentials
 *     fs.s3a.ext.lakefs.broker.spn    = HTTP@lakefs-sts.corp.example.mil   (optional; derived from url)
 *
 * Dependencies are all "provided" by the Hadoop/S3A runtime (hadoop-aws,
 * aws-java-sdk-bundle). No JSON library is used, to keep the jar dependency-free.
 */
package com.example.lakefs;

import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import org.apache.hadoop.conf.Configuration;
import org.ietf.jgss.*;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;

public class LakeFSKerberosCredentialProvider implements AWSCredentialsProvider {

    private static final Oid SPNEGO = oid("1.3.6.1.5.5.2");
    private static final long SKEW_SECONDS = 60;      // refresh this long before expiry

    private final String brokerUrl;
    private final String spn;                         // GSS host-based service: HTTP@host

    private volatile AWSCredentials cached;
    private volatile Instant expiresAt = Instant.EPOCH;

    /** S3A instantiates custom providers with (URI, Configuration). */
    public LakeFSKerberosCredentialProvider(URI uri, Configuration conf) {
        this.brokerUrl = require(conf, "fs.s3a.ext.lakefs.broker.url");
        String configured = conf.get("fs.s3a.ext.lakefs.broker.spn");
        this.spn = (configured != null && !configured.isEmpty())
                ? configured : "HTTP@" + hostOf(this.brokerUrl);
    }

    @Override
    public AWSCredentials getCredentials() {
        AWSCredentials c = cached;
        if (c != null && Instant.now().isBefore(expiresAt.minusSeconds(SKEW_SECONDS))) {
            return c;                                  // still fresh
        }
        synchronized (this) {
            if (cached != null && Instant.now().isBefore(expiresAt.minusSeconds(SKEW_SECONDS))) {
                return cached;
            }
            try {
                fetch();
            } catch (Exception e) {
                throw new RuntimeException("lakeFS credential broker exchange failed: " + e, e);
            }
            return cached;
        }
    }

    @Override
    public void refresh() {
        expiresAt = Instant.EPOCH;
    }

    private void fetch() throws Exception {
        String token = spnegoToken(spn);              // Kerberos service ticket -> SPNEGO blob
        HttpURLConnection c = (HttpURLConnection) new URL(brokerUrl).openConnection();
        c.setRequestMethod("POST");
        c.setRequestProperty("Authorization", "Negotiate " + token);
        c.setConnectTimeout(10_000);
        c.setReadTimeout(15_000);
        int code = c.getResponseCode();
        if (code == HttpURLConnection.HTTP_UNAUTHORIZED) {
            throw new IOException("broker returned 401 (SPNEGO rejected; check SPN/keytab/clock)");
        }
        if (code >= 300) {
            throw new IOException("broker returned HTTP " + code);
        }
        String body;
        try (InputStream in = c.getInputStream()) {
            body = new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
        String akid   = jsonField(body, "access_key_id");
        String secret = jsonField(body, "secret_access_key");
        String expiry = jsonField(body, "expiry");
        if (akid == null || secret == null) {
            throw new IOException("broker response missing key fields: " + body);
        }
        this.cached = new BasicAWSCredentials(akid, secret);
        this.expiresAt = (expiry != null) ? Instant.parse(expiry) : Instant.now().plusSeconds(600);
    }

    /** Build a one-shot SPNEGO token for {@code service} using the ambient ccache. */
    private static String spnegoToken(String service) throws GSSException {
        GSSManager mgr = GSSManager.getInstance();
        GSSName target = mgr.createName(service, GSSName.NT_HOSTBASED_SERVICE);
        // null credential => use the default (native ccache: KRB5CCNAME). With
        // -Dsun.security.jgss.native=true this uses the pre-minted service ticket.
        GSSContext ctx = mgr.createContext(target, SPNEGO, null, GSSContext.DEFAULT_LIFETIME);
        ctx.requestMutualAuth(false);
        ctx.requestCredDeleg(false);
        byte[] out = ctx.initSecContext(new byte[0], 0, 0);
        ctx.dispose();
        return Base64.getEncoder().encodeToString(out);
    }

    // --- tiny helpers (no external JSON dependency) ---
    private static String jsonField(String json, String key) {
        String needle = "\"" + key + "\"";
        int k = json.indexOf(needle);
        if (k < 0) return null;
        int colon = json.indexOf(':', k + needle.length());
        if (colon < 0) return null;
        int i = colon + 1;
        while (i < json.length() && Character.isWhitespace(json.charAt(i))) i++;
        if (i >= json.length() || json.charAt(i) != '"') return null;    // only string values
        int start = i + 1, end = start;
        StringBuilder sb = new StringBuilder();
        while (end < json.length() && json.charAt(end) != '"') {
            char ch = json.charAt(end);
            if (ch == '\\' && end + 1 < json.length()) { sb.append(json.charAt(end + 1)); end += 2; }
            else { sb.append(ch); end++; }
        }
        return sb.toString();
    }

    private static String hostOf(String url) {
        try { return new URI(url).getHost(); }
        catch (Exception e) { throw new IllegalArgumentException("bad broker url: " + url, e); }
    }

    private static String require(Configuration conf, String key) {
        String v = conf.get(key);
        if (v == null || v.isEmpty()) throw new IllegalArgumentException("missing config: " + key);
        return v;
    }

    private static Oid oid(String s) {
        try { return new Oid(s); } catch (GSSException e) { throw new RuntimeException(e); }
    }
}
