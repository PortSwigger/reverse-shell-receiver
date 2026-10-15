package burp.payload;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Handles various encoding, wrapping, and obfuscation schemes for generated payloads.
 */
public final class PayloadEncoder {

    public enum EncodingType {
        RAW("None (Raw)"),
        BASE64("Base64 (Standard)"),
        BASE64_SH_WRAPPED("Base64 (Linux sh wrapped)"),
        BASE64_BASH_WRAPPED("Base64 (Linux bash wrapped)"),
        POWERSHELL_B64("PowerShell EncodedCommand (-enc)"),
        URL_STANDARD("URL Encode (Standard)"),
        URL_ALL_CHARS("URL Encode All (Full Hex %XX)"),
        URL_DOUBLE("Double URL Encode"),
        HEX_ESCAPED("Hex Escaped (\\x41\\x42...)"),
        HTML_ENTITIES("HTML Entity (&#x41;&#x42;...)");

        private final String displayName;

        EncodingType(String displayName) {
            this.displayName = displayName;
        }

        public String getDisplayName() {
            return displayName;
        }

        @Override
        public String toString() {
            return displayName;
        }

        public static EncodingType fromDisplayName(String name) {
            for (EncodingType type : values()) {
                if (type.displayName.equalsIgnoreCase(name)) {
                    return type;
                }
            }
            return RAW;
        }
    }

    private PayloadEncoder() {}

    public static String encode(String rawPayload, EncodingType encoding) {
        if (rawPayload == null || rawPayload.isEmpty()) {
            return "";
        }

        switch (encoding) {
            case BASE64:
                return Base64.getEncoder().encodeToString(rawPayload.getBytes(StandardCharsets.UTF_8));

            case BASE64_SH_WRAPPED: {
                String b64 = Base64.getEncoder().encodeToString(rawPayload.getBytes(StandardCharsets.UTF_8));
                return "echo " + b64 + " | base64 -d | sh";
            }

            case BASE64_BASH_WRAPPED: {
                String b64 = Base64.getEncoder().encodeToString(rawPayload.getBytes(StandardCharsets.UTF_8));
                return "echo " + b64 + " | base64 -d | bash";
            }

            case POWERSHELL_B64: {
                // PowerShell EncodedCommand requires UTF-16LE encoding before Base64
                byte[] utf16le = rawPayload.getBytes(StandardCharsets.UTF_16LE);
                String b64 = Base64.getEncoder().encodeToString(utf16le);
                return "powershell.exe -NoP -NonI -W Hidden -Enc " + b64;
            }

            case URL_STANDARD: {
                try {
                    return URLEncoder.encode(rawPayload, "UTF-8");
                } catch (UnsupportedEncodingException e) {
                    return rawPayload;
                }
            }

            case URL_ALL_CHARS: {
                StringBuilder sb = new StringBuilder();
                byte[] bytes = rawPayload.getBytes(StandardCharsets.UTF_8);
                for (byte b : bytes) {
                    sb.append(String.format("%%%02X", b & 0xFF));
                }
                return sb.toString();
            }

            case URL_DOUBLE: {
                try {
                    String once = URLEncoder.encode(rawPayload, "UTF-8");
                    return URLEncoder.encode(once, "UTF-8");
                } catch (UnsupportedEncodingException e) {
                    return rawPayload;
                }
            }

            case HEX_ESCAPED: {
                StringBuilder sb = new StringBuilder();
                byte[] bytes = rawPayload.getBytes(StandardCharsets.UTF_8);
                for (byte b : bytes) {
                    sb.append(String.format("\\x%02x", b & 0xFF));
                }
                return sb.toString();
            }

            case HTML_ENTITIES: {
                StringBuilder sb = new StringBuilder();
                for (char c : rawPayload.toCharArray()) {
                    sb.append("&#x").append(Integer.toHexString(c)).append(";");
                }
                return sb.toString();
            }

            case RAW:
            default:
                return rawPayload;
        }
    }
}
