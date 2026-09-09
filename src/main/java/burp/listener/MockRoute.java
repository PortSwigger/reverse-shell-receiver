package burp.listener;

import java.nio.charset.StandardCharsets;

/**
 * Defines a custom mock endpoint route for the Webhook HTTP Listener.
 */
public class MockRoute {

    public enum MatchType {
        EXACT("Exact Match"),
        PREFIX("Starts With (Prefix)"),
        REGEX("Regular Expression");

        private final String displayName;
        MatchType(String displayName) { this.displayName = displayName; }
        public String getDisplayName() { return displayName; }
        @Override public String toString() { return displayName; }
    }

    private String path;
    private MatchType matchType = MatchType.EXACT;
    private String statusCode = "200 OK";
    private String contentType = "text/plain; charset=utf-8";
    private String responseBody = "";
    private String redirectLocation = "";
    private boolean enabled = true;
    private String description = "";

    public MockRoute(String path, MatchType matchType, String statusCode, String contentType, String responseBody, String redirectLocation, String description) {
        this.path = path;
        this.matchType = matchType;
        this.statusCode = statusCode;
        this.contentType = contentType;
        this.responseBody = responseBody;
        this.redirectLocation = redirectLocation;
        this.description = description;
    }

    public boolean matches(String requestPath) {
        if (!enabled || requestPath == null) return false;
        String cleanReq = requestPath.split("\\?")[0].trim();
        switch (matchType) {
            case EXACT:
                return cleanReq.equalsIgnoreCase(path.trim());
            case PREFIX:
                return cleanReq.toLowerCase().startsWith(path.toLowerCase().trim());
            case REGEX:
                try {
                    return cleanReq.matches(path.trim());
                } catch (Exception e) {
                    return false;
                }
            default:
                return false;
        }
    }

    public byte[] buildResponseBytes(boolean enableCors) {
        byte[] bodyBytes = responseBody != null ? responseBody.getBytes(StandardCharsets.UTF_8) : new byte[0];

        StringBuilder headerBuilder = new StringBuilder();
        headerBuilder.append("HTTP/1.1 ").append(statusCode).append("\r\n");
        headerBuilder.append("Server: ReverseShellReceiver-MockRoute/2.0\r\n");
        headerBuilder.append("Content-Type: ").append(contentType).append("\r\n");
        headerBuilder.append("Content-Length: ").append(bodyBytes.length).append("\r\n");
        headerBuilder.append("Connection: close\r\n");

        if (enableCors) {
            headerBuilder.append("Access-Control-Allow-Origin: *\r\n");
            headerBuilder.append("Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS, HEAD\r\n");
            headerBuilder.append("Access-Control-Allow-Headers: *\r\n");
        }

        if ((statusCode.startsWith("301") || statusCode.startsWith("302") || statusCode.startsWith("307") || statusCode.startsWith("308"))
                && redirectLocation != null && !redirectLocation.trim().isEmpty()) {
            headerBuilder.append("Location: ").append(redirectLocation.trim()).append("\r\n");
        }

        headerBuilder.append("\r\n");

        byte[] headerBytes = headerBuilder.toString().getBytes(StandardCharsets.UTF_8);
        byte[] fullResponse = new byte[headerBytes.length + bodyBytes.length];
        System.arraycopy(headerBytes, 0, fullResponse, 0, headerBytes.length);
        System.arraycopy(bodyBytes, 0, fullResponse, headerBytes.length, bodyBytes.length);

        return fullResponse;
    }

    // Getters and Setters
    public String getPath() { return path; }
    public void setPath(String path) { this.path = path; }

    public MatchType getMatchType() { return matchType; }
    public void setMatchType(MatchType matchType) { this.matchType = matchType; }

    public String getStatusCode() { return statusCode; }
    public void setStatusCode(String statusCode) { this.statusCode = statusCode; }

    public String getContentType() { return contentType; }
    public void setContentType(String contentType) { this.contentType = contentType; }

    public String getResponseBody() { return responseBody; }
    public void setResponseBody(String responseBody) { this.responseBody = responseBody; }

    public String getRedirectLocation() { return redirectLocation; }
    public void setRedirectLocation(String redirectLocation) { this.redirectLocation = redirectLocation; }

    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }

    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
}
