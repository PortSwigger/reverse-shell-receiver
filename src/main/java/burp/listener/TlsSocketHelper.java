package burp.listener;

import burp.IBurpExtenderCallbacks;

import javax.net.ssl.*;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Base64;

/**
 * Creates SSL/TLS Server Sockets for encrypted reverse shell listeners (PowerShell TLS, Ncat SSL, Socat OpenSSL)
 * and HTTPS Webhooks with a uniquely generated 2048-bit RSA self-signed certificate, persisted per installation.
 */
public final class TlsSocketHelper {

    private static final String SETTING_KEYSTORE_B64 = "tls_keystore_b64";
    private static final String SETTING_KEYSTORE_PWD = "tls_keystore_password";

    // Pre-computed AlgorithmIdentifier for SHA256withRSA: 1.2.840.113549.1.1.11 with NULL parameters
    private static final byte[] SHA256_WITH_RSA_ALG_ID = new byte[] {
            0x30, 0x0d, 0x06, 0x09, 0x2a, (byte) 0x86, 0x48, (byte) 0x86,
            (byte) 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00
    };

    private static volatile SSLContext cachedSslContext = null;

    private TlsSocketHelper() {}

    public static SSLServerSocket createTlsServerSocket(int port, int backlog, InetAddress bindAddr) throws Exception {
        return createTlsServerSocket(port, backlog, bindAddr, null);
    }

    public static SSLServerSocket createTlsServerSocket(int port, int backlog, InetAddress bindAddr, IBurpExtenderCallbacks callbacks) throws Exception {
        SSLContext sslContext = createSslContext(callbacks);
        SSLServerSocketFactory factory = sslContext.getServerSocketFactory();
        SSLServerSocket serverSocket = (SSLServerSocket) factory.createServerSocket(port, backlog, bindAddr);
        serverSocket.setNeedClientAuth(false);
        serverSocket.setWantClientAuth(false);
        return serverSocket;
    }

    public static SSLContext createSslContext() throws Exception {
        return createSslContext(null);
    }

    public static synchronized SSLContext createSslContext(IBurpExtenderCallbacks callbacks) throws Exception {
        if (cachedSslContext != null && callbacks == null) {
            return cachedSslContext;
        }

        KeyStore keyStore = null;
        char[] password = null;

        if (callbacks != null) {
            String savedKsB64 = callbacks.loadExtensionSetting(SETTING_KEYSTORE_B64);
            String savedPwd = callbacks.loadExtensionSetting(SETTING_KEYSTORE_PWD);
            if (savedKsB64 != null && !savedKsB64.trim().isEmpty() && savedPwd != null && !savedPwd.trim().isEmpty()) {
                try {
                    KeyStore ks = KeyStore.getInstance("PKCS12");
                    byte[] ksBytes = Base64.getDecoder().decode(savedKsB64.trim());
                    try (InputStream is = new ByteArrayInputStream(ksBytes)) {
                        ks.load(is, savedPwd.toCharArray());
                    }
                    keyStore = ks;
                    password = savedPwd.toCharArray();
                } catch (Exception e) {
                    callbacks.printError("Failed to load persisted TLS certificate, generating a new one: " + e.getMessage());
                    keyStore = null;
                }
            }
        }

        if (keyStore == null) {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048, new SecureRandom());
            KeyPair keyPair = kpg.generateKeyPair();
            X509Certificate cert = generateSelfSignedCertificate(keyPair, "Reverse Shell Receiver");

            password = generateSecurePassword().toCharArray();
            keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, password);
            keyStore.setKeyEntry("listener", keyPair.getPrivate(), password, new Certificate[] { cert });

            if (callbacks != null) {
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                keyStore.store(baos, password);
                String b64 = Base64.getEncoder().encodeToString(baos.toByteArray());
                callbacks.saveExtensionSetting(SETTING_KEYSTORE_B64, b64);
                callbacks.saveExtensionSetting(SETTING_KEYSTORE_PWD, new String(password));
                callbacks.printOutput("Generated and persisted unique 2048-bit RSA TLS certificate for this Burp Suite installation.");
            }
        }

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, password);

        TrustManager[] trustAllCerts = new TrustManager[] {
                new X509TrustManager() {
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() { return null; }
                    public void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType) {}
                    public void checkServerTrusted(java.security.cert.X509Certificate[] certs, String authType) {}
                }
        };

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kmf.getKeyManagers(), trustAllCerts, new SecureRandom());
        cachedSslContext = sslContext;
        return sslContext;
    }

    private static String generateSecurePassword() {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[24];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /**
     * Generates a compliant self-signed X.509 v3 certificate without external dependencies.
     */
    public static X509Certificate generateSelfSignedCertificate(KeyPair keyPair, String commonName) throws Exception {
        byte[] versionExplicit = derTagged(0xA0, derInteger(BigInteger.valueOf(2))); // v3

        BigInteger serial = new BigInteger(64, new SecureRandom()).abs();
        if (serial.equals(BigInteger.ZERO)) serial = BigInteger.ONE;
        byte[] serialNumber = derInteger(serial);

        byte[] sigAlg = SHA256_WITH_RSA_ALG_ID;
        byte[] issuer = createDistinguishedName(commonName);
        byte[] subject = issuer;

        Instant notBefore = Instant.now().minusSeconds(3600);
        Instant notAfter = notBefore.plusSeconds(10L * 365 * 24 * 3600); // 10 years validity
        byte[] validity = derSequence(derUtcTime(notBefore), derUtcTime(notAfter));

        byte[] subjectPublicKeyInfo = keyPair.getPublic().getEncoded();

        byte[] tbsCertificate = derSequence(
                versionExplicit,
                serialNumber,
                sigAlg,
                issuer,
                validity,
                subject,
                subjectPublicKeyInfo
        );

        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(keyPair.getPrivate());
        signature.update(tbsCertificate);
        byte[] signatureBytes = signature.sign();

        byte[] sigBitString = derBitString(signatureBytes);

        byte[] certificateBytes = derSequence(
                tbsCertificate,
                sigAlg,
                sigBitString
        );

        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        return (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(certificateBytes));
    }

    // --- DER ASN.1 Encoding Helpers ---

    private static byte[] derEncodeLength(int length) {
        if (length < 128) {
            return new byte[] { (byte) length };
        } else if (length < 256) {
            return new byte[] { (byte) 0x81, (byte) length };
        } else if (length < 65536) {
            return new byte[] { (byte) 0x82, (byte) (length >> 8), (byte) length };
        } else {
            return new byte[] { (byte) 0x83, (byte) (length >> 16), (byte) (length >> 8), (byte) length };
        }
    }

    private static byte[] derSequence(byte[]... elements) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        for (byte[] el : elements) {
            if (el != null) baos.write(el);
        }
        byte[] body = baos.toByteArray();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0x30); // SEQUENCE tag
        out.write(derEncodeLength(body.length));
        out.write(body);
        return out.toByteArray();
    }

    private static byte[] derTagged(int tag, byte[] content) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(tag);
        out.write(derEncodeLength(content.length));
        out.write(content);
        return out.toByteArray();
    }

    private static byte[] derInteger(BigInteger val) throws IOException {
        byte[] bytes = val.toByteArray();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0x02); // INTEGER tag
        out.write(derEncodeLength(bytes.length));
        out.write(bytes);
        return out.toByteArray();
    }

    private static byte[] derBitString(byte[] content) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0x03); // BIT STRING tag
        out.write(derEncodeLength(content.length + 1));
        out.write(0x00); // 0 unused bits
        out.write(content);
        return out.toByteArray();
    }

    private static byte[] derUtcTime(Instant instant) throws IOException {
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyMMddHHmmss'Z'").withZone(ZoneOffset.UTC);
        byte[] timeBytes = formatter.format(instant).getBytes(StandardCharsets.US_ASCII);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0x17); // UTCTime tag
        out.write(derEncodeLength(timeBytes.length));
        out.write(timeBytes);
        return out.toByteArray();
    }

    private static byte[] createDistinguishedName(String commonName) throws IOException {
        byte[] attrType = new byte[] { 0x06, 0x03, 0x55, 0x04, 0x03 }; // id-at-commonName 2.5.4.3
        byte[] cnBytes = commonName.getBytes(StandardCharsets.UTF_8);

        ByteArrayOutputStream utf8 = new ByteArrayOutputStream();
        utf8.write(0x0C); // UTF8String tag
        utf8.write(derEncodeLength(cnBytes.length));
        utf8.write(cnBytes);

        byte[] attrValue = utf8.toByteArray();
        byte[] attrSeq = derSequence(attrType, attrValue);

        ByteArrayOutputStream set = new ByteArrayOutputStream();
        set.write(0x31); // SET tag
        set.write(derEncodeLength(attrSeq.length));
        set.write(attrSeq);

        return derSequence(set.toByteArray());
    }
}
