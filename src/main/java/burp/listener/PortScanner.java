package burp.listener;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Cross-platform TCP port scanner and process terminator utility.
 */
public final class PortScanner {

    public static class PortInfo {
        private final int port;
        private final String protocol;
        private final String localAddress;
        private final int pid;
        private final String processName;

        public PortInfo(int port, String protocol, String localAddress, int pid, String processName) {
            this.port = port;
            this.protocol = protocol;
            this.localAddress = localAddress;
            this.pid = pid;
            this.processName = processName;
        }

        public int getPort() { return port; }
        public String getProtocol() { return protocol; }
        public String getLocalAddress() { return localAddress; }
        public int getPid() { return pid; }
        public String getProcessName() { return processName; }
    }

    private PortScanner() {}

    public static List<PortInfo> getUsedPorts() {
        List<PortInfo> usedPorts = new ArrayList<>();
        String os = System.getProperty("os.name").toLowerCase();

        try {
            Map<Integer, String> processMap = os.contains("win") ? getWindowsProcessMap() : new HashMap<>();

            Process process = os.contains("win")
                    ? new ProcessBuilder("cmd", "/c", "netstat -aon | findstr LISTENING").start()
                    : new ProcessBuilder("netstat", "-tulnp").start();

            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                Pattern pattern = os.contains("win")
                        ? Pattern.compile("\\s*TCP\\s+(\\S+):(\\d+)\\s+\\S+\\s+LISTENING\\s+(\\d+)")
                        : Pattern.compile("tcp\\s+\\d+\\s+\\d+\\s+(\\S+):(\\d+)\\s+.*LISTEN\\s+(\\d+)/(\\S+)");

                while ((line = reader.readLine()) != null) {
                    Matcher matcher = pattern.matcher(line);
                    if (matcher.find()) {
                        String localAddress = matcher.group(1);
                        int port = Integer.parseInt(matcher.group(2));
                        int pid = matcher.group(3) != null ? Integer.parseInt(matcher.group(3)) : -1;

                        String processName = "Unknown";
                        if (os.contains("win")) {
                            processName = processMap.getOrDefault(pid, "Unknown");
                        } else if (matcher.groupCount() >= 4) {
                            processName = matcher.group(4);
                        }

                        usedPorts.add(new PortInfo(port, "TCP", localAddress, pid, processName));
                    }
                }
            }
            process.waitFor();
        } catch (IOException | InterruptedException e) {
            // Return whatever was collected
        }
        return usedPorts;
    }

    private static Map<Integer, String> getWindowsProcessMap() {
        Map<Integer, String> processMap = new HashMap<>();
        try {
            Process process = new ProcessBuilder("tasklist", "/fo", "csv", "/nh").start();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    String[] parts = line.split("\",\"");
                    if (parts.length >= 2) {
                        try {
                            String name = parts[0].replace("\"", "");
                            String pidStr = parts[1].replace("\"", "");
                            processMap.put(Integer.parseInt(pidStr), name);
                        } catch (NumberFormatException ignored) {}
                    }
                }
            }
        } catch (IOException ignored) {}
        return processMap;
    }

    public static boolean killProcess(int pid) {
        if (pid <= 0) return false;
        String os = System.getProperty("os.name").toLowerCase();
        try {
            ProcessBuilder pb = os.contains("win")
                    ? new ProcessBuilder("taskkill", "/PID", String.valueOf(pid), "/F")
                    : new ProcessBuilder("kill", "-9", String.valueOf(pid));
            Process process = pb.start();
            return process.waitFor() == 0;
        } catch (IOException | InterruptedException e) {
            return false;
        }
    }
}
