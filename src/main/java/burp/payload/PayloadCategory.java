package burp.payload;

public enum PayloadCategory {
    REVERSE_SHELL("Reverse Shell"),
    BIND_SHELL("Bind Shell"),
    WEB_SHELL("Web Shell"),
    DATA_EXFILTRATION("Data Exfiltration"),
    STAGERS_HELPERS("Stagers & Helpers");

    private final String displayName;

    PayloadCategory(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() {
        return displayName;
    }

    @Override
    public String toString() {
        return displayName;
    }

    public static PayloadCategory fromDisplayName(String name) {
        for (PayloadCategory cat : values()) {
            if (cat.displayName.equalsIgnoreCase(name)) {
                return cat;
            }
        }
        return REVERSE_SHELL;
    }
}
