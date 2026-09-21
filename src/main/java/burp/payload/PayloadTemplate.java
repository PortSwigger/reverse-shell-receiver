package burp.payload;

public class PayloadTemplate {

    public interface Generator {
        String generate(PayloadParams params);
    }

    public static class PayloadParams {
        public String ip = "127.0.0.1";
        public int port = 4444;
        public String shellPath = "/bin/bash";
        public String targetFile = "/etc/passwd";
        public String customCommand = "whoami";

        public PayloadParams(String ip, int port, String shellPath, String targetFile, String customCommand) {
            if (ip != null && !ip.trim().isEmpty()) this.ip = ip.trim();
            if (port > 0) this.port = port;
            if (shellPath != null && !shellPath.trim().isEmpty()) this.shellPath = shellPath.trim();
            if (targetFile != null && !targetFile.trim().isEmpty()) this.targetFile = targetFile.trim();
            if (customCommand != null && !customCommand.trim().isEmpty()) this.customCommand = customCommand.trim();
        }
    }

    private final String id;
    private final String name;
    private final PayloadCategory category;
    private final String targetOS;
    private final String description;
    private final boolean requiresIp;
    private final boolean requiresPort;
    private final boolean requiresShellPath;
    private final boolean requiresFileOrCmd;
    private final Generator generator;

    public PayloadTemplate(String id, String name, PayloadCategory category, String targetOS,
                           String description, boolean requiresIp, boolean requiresPort,
                           boolean requiresShellPath, boolean requiresFileOrCmd,
                           Generator generator) {
        this.id = id;
        this.name = name;
        this.category = category;
        this.targetOS = targetOS;
        this.description = description;
        this.requiresIp = requiresIp;
        this.requiresPort = requiresPort;
        this.requiresShellPath = requiresShellPath;
        this.requiresFileOrCmd = requiresFileOrCmd;
        this.generator = generator;
    }

    public String getId() { return id; }
    public String getName() { return name; }
    public PayloadCategory getCategory() { return category; }
    public String getTargetOS() { return targetOS; }
    public String getDescription() { return description; }
    public boolean isRequiresIp() { return requiresIp; }
    public boolean isRequiresPort() { return requiresPort; }
    public boolean isRequiresShellPath() { return requiresShellPath; }
    public boolean isRequiresFileOrCmd() { return requiresFileOrCmd; }

    public String generate(PayloadParams params) {
        return generator.generate(params);
    }

    @Override
    public String toString() {
        return name + " (" + targetOS + ")";
    }
}
