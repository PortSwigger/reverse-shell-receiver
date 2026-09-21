package burp;

import burp.listener.WebhookResponseConfig;
import org.junit.Test;
import java.nio.charset.StandardCharsets;
import static org.junit.Assert.*;

public class WebhookResponseTest {

    @Test
    public void testDynamicWebhookResponse() {
        WebhookResponseConfig config = new WebhookResponseConfig();
        byte[] responseBytes = config.buildResponseBytes(
                "192.168.1.55",
                "POST",
                "/api/v1/telemetry",
                8080,
                "Host: 192.168.1.55:8080\nUser-Agent: Mozilla/5.0\nContent-Type: application/json",
                128
        );

        assertNotNull(responseBytes);
        assertTrue(responseBytes.length > 0);

        String responseStr = new String(responseBytes, StandardCharsets.UTF_8);
        assertTrue(responseStr.startsWith("HTTP/1.1 200 OK"));
        assertTrue(responseStr.contains("Reverse Shell Receiver"));
        assertTrue(responseStr.contains("READY FOR INTERACTION"));
        assertTrue(responseStr.contains("192.168.1.55"));
        assertTrue(responseStr.contains("POST"));
        assertTrue(responseStr.contains("/api/v1/telemetry"));
        assertTrue(responseStr.contains("128 Bytes"));
        assertTrue(responseStr.contains("Access-Control-Allow-Origin: *"));
    }
}
