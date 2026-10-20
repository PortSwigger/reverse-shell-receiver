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
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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
    private volatile LocalDateTime closedAt = null;
    private volatile SessionShellType shellType = SessionShellType.UNIX;
    private volatile String currentRemotePath = "~";
    private volatile String lastCommand = "";
    private volatile String pendingEchoCommand = null;
    private volatile boolean awaitingCommandOutput = false;
    private volatile long bytesReceived = 0;

    private volatile String lastAppendedPrompt = null;
    private volatile boolean lastOutputWasPrompt = false;
    private String pendingResidual = "";

    // ANSI & Terminal Control regex patterns
    private static final Pattern PATTERN_OSC =
            Pattern.compile("(?:\u001B\\]|\u009D|\\][0-9]+;)[^\u0007\u001B\u009C\r\n┌└]*+(?:[\u0007]|\u001B\\\\|\u009C|(?=[┌└])|[\\r\\n]|$)");
    private static final Pattern PATTERN_BARE_OSC =
            Pattern.compile("(?m)^\\][0-9]+;[^\r\n┌└]*+(?:(?=[┌└])|[\\r\\n]|$)");
    private static final Pattern PATTERN_DCS =
            Pattern.compile("(?:\u001B[P^_]|\u0090|\u009E|\u009F)[^\u0007\u001B\u009C]*+(?:[\u0007]|\u001B\\\\|\u009C|$)");
    private static final Pattern PATTERN_CSI =
            Pattern.compile("(?:\u001B\\[|\u009B)[0-9:;<=>?]*+[ -/]*+[@-~]");
    private static final Pattern PATTERN_CHARSET =
            Pattern.compile("\u001B[()%*+-][A-Za-z0-9]");
    private static final Pattern PATTERN_ESC2 =
            Pattern.compile("\u001B[@-_]");
    private static final Pattern PATTERN_CONTROL_CHARS =
            Pattern.compile("[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]");
    private static final Pattern PATTERN_EXCESS_NEWLINES =
            Pattern.compile("\n{3,}");

    // Passive Prompt Extraction patterns
    private static final Pattern PATTERN_UNIX_PATH =
            Pattern.compile("-\\[([^\\]]+)\\]\\s*$");
    private static final Pattern PATTERN_WIN_PATH =
            Pattern.compile("(?:PS\\s+)?([A-Za-z]:\\\\[^>\\r\\n]*)>");
    private static final Pattern PATTERN_STD_UNIX_PATH =
            Pattern.compile("[\\w.-]+@[\\w.-]+:([^$#\\r\\n]+)[$#]\\s*$");

    private BufferedWriter writer;
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

        this.writer = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.UTF_8));
        this.reader = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));

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
        readerThread = new Thread(() -> {
            try {
                char[] buffer = new char[4096];
                int charsRead;

                while (active && (charsRead = reader.read(buffer)) != -1) {
                    bytesReceived += charsRead;
                    String chunk = new String(buffer, 0, charsRead);

                    String cleanChunk = processIncomingChunk(chunk);
                    if (cleanChunk.isEmpty()) continue;

                    appendOutput(cleanChunk, styleNormal);
                    if (listener != null) listener.onSessionOutput(this, cleanChunk);
                }
            } catch (IOException e) {
                if (active && callbacks != null) {
                    callbacks.printError("Session #" + id + " connection broken unexpectedly: " + e.getMessage());
                }
            } finally {
                active = false;
                if (closedAt == null) {
                    closedAt = LocalDateTime.now();
                }
                appendOutput("\n[SESSION #" + id + " DISCONNECTED]\n\n", styleStatus);
                if (listener != null) listener.onSessionTerminated(this);
            }
        });
        readerThread.setDaemon(true);
        readerThread.start();
    }

    /**
     * Processes incoming raw TCP chunks statefully:
     * 1. Preserves partial escape sequences split across packet boundaries.
     * 2. Passively detects remote shell type and directory path.
     * 3. Cleans OSC window titles, ANSI escapes, unprintable control chars, and CRLF.
     * 4. Suppresses remote command echo and stray pre-execution prompts.
     * 5. Eliminates duplicate prompts across TCP packets and collapse excess blank lines.
     */
    public synchronized String processIncomingChunk(String rawChunk) {
        if (rawChunk == null || rawChunk.isEmpty()) return "";

        // Combine with any residual partial sequence from previous packet
        String fullChunk = pendingResidual + rawChunk;
        pendingResidual = "";

        // Passive OS and path detection before stripping
        detectShellTypePassively(fullChunk);
        updateRemotePathPassively(fullChunk);

        // Backward-compatibility: if an explicit OS probe response was received
        if (fullChunk.contains("___OS_PROBE___")) {
            if (fullChunk.contains("Windows_NT")) {
                shellType = fullChunk.contains("%OS%") ? SessionShellType.WINDOWS_PS : SessionShellType.WINDOWS_CMD;
            } else {
                shellType = SessionShellType.UNIX;
            }
            if (listener != null) listener.onPathUpdated(this, currentRemotePath);
            fullChunk = fullChunk.replaceAll("(?m)^.*___OS_PROBE___.*$[\r\n]*", "");
        }

        // Buffer incomplete trailing escape sequences so they don't leak into terminal
        int incompleteIdx = findIncompleteEscapeIndex(fullChunk);
        if (incompleteIdx != -1) {
            pendingResidual = fullChunk.substring(incompleteIdx);
            fullChunk = fullChunk.substring(0, incompleteIdx);
        }

        if (fullChunk.isEmpty()) return "";

        // Clean ANSI terminal sequences, control characters, CRLF, and excess newlines
        String cleanChunk = sanitizeTerminalOutput(fullChunk);

        // If no user command has been dispatched yet, suppress initial shell connection prompt
        if (commandHistory.isEmpty() && isInitialPromptChunk(cleanChunk)) {
            return "";
        }

        // Suppress remote command echo and stray pre-execution prompt redraws across TCP packets
        if (pendingEchoCommand != null || awaitingCommandOutput) {
            cleanChunk = suppressCommandEcho(cleanChunk);
        }

        // Strip remote prompts completely so only clean Burp prompt and command output remain
        cleanChunk = stripRemotePrompts(cleanChunk);

        return cleanChunk;
    }

    /**
     * Detects if the chunk ends with an incomplete escape sequence split by TCP packet boundaries.
     */
    private int findIncompleteEscapeIndex(String s) {
        if (s == null || s.isEmpty()) return -1;
        int len = s.length();
        int searchStart = Math.max(0, len - 64);

        int lastEsc = s.lastIndexOf('\u001B', len - 1);
        if (lastEsc >= searchStart) {
            String tail = s.substring(lastEsc);
            // Incomplete CSI: ESC [ ... without terminating character [@-~]
            if (tail.startsWith("\u001B[")) {
                if (tail.length() == 2 || !tail.substring(2).matches(".*[@-~].*")) {
                    return lastEsc;
                }
            } else if (tail.startsWith("\u001B]")) {
                // Incomplete OSC: ESC ] ... without BEL, ST, or newline
                if (!tail.contains("\u0007") && !tail.contains("\u001B\\") && !tail.contains("\n")) {
                    return lastEsc;
                }
            } else if (tail.equals("\u001B")) {
                return lastEsc;
            }
        }

        // Bare ]0; without termination
        int lastBracket = s.lastIndexOf(']');
        if (lastBracket >= searchStart && lastBracket + 2 <= len) {
            char next = s.charAt(lastBracket + 1);
            if (Character.isDigit(next)) {
                String tail = s.substring(lastBracket);
                if (!tail.contains("\u0007") && !tail.contains("\n") && !tail.contains("\r")) {
                    return lastBracket;
                }
            }
        }

        return -1;
    }

    /**
     * Sanitizes raw terminal output:
     * 1. Strips OSC (Operating System Command) window title / hyperlink sequences (e.g. \033]0;title\007)
     * 2. Strips DCS, PM, APC terminal control sequences
     * 3. Strips CSI escape sequences (colors, cursor positioning, bracketed paste mode, etc.)
     * 4. Strips 2-byte escape sequences and character set definitions
     * 5. Strips unprintable ASCII control characters except \t, \n, and \r
     * 6. Normalizes CRLF (\r\n) and prevents carriage returns (\r) from turning into phantom duplicate newlines
     * 7. Collapses 3 or more consecutive blank lines into 2
     */
    public static String sanitizeTerminalOutput(String chunk) {
        if (chunk == null || chunk.isEmpty()) return "";

        // 1. Strip OSC sequences: ESC ] ... (BEL | ESC \ | 0x9C | EOF) and bare ]0; window titles
        String text = PATTERN_OSC.matcher(chunk).replaceAll("");
        text = PATTERN_BARE_OSC.matcher(text).replaceAll("");

        // 2. Strip DCS, PM, APC sequences: ESC [P^_] ... (BEL | ESC \ | 0x9C | EOF)
        text = PATTERN_DCS.matcher(text).replaceAll("");

        // 3. Strip CSI sequences: ESC [ ... [final byte 0x40-0x7E]
        text = PATTERN_CSI.matcher(text).replaceAll("");

        // 4. Strip character set definitions and 2-byte escape sequences
        text = PATTERN_CHARSET.matcher(text).replaceAll("");
        text = PATTERN_ESC2.matcher(text).replaceAll("");

        // 5. Strip unprintable control characters (preserve \t=0x09, \n=0x0A, \r=0x0D)
        text = PATTERN_CONTROL_CHARS.matcher(text).replaceAll("");

        // 6. Process carriage returns (\r\n -> \n, lone \r -> overwrite from column 0)
        text = processCarriageReturns(text);

        // 7. Deduplicate redundant shell prompts
        text = deduplicatePrompts(text);

        // 8. Collapse excessive consecutive blank lines (3+ newlines -> 2 newlines)
        text = PATTERN_EXCESS_NEWLINES.matcher(text).replaceAll("\n\n");

        return text;
    }

    /**
     * Emulates terminal carriage return behavior:
     * Converts \r\n to \n.
     * Treats lone \r as moving the cursor to column 0 of the current line,
     * allowing subsequent characters to overwrite preceding characters on that line.
     */
    public static String processCarriageReturns(String text) {
        if (text == null || !text.contains("\r")) {
            return text;
        }
        StringBuilder result = new StringBuilder(text.length());
        StringBuilder currentLine = new StringBuilder();
        int linePos = 0;

        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c == '\r') {
                if (i + 1 < text.length() && text.charAt(i + 1) == '\n') {
                    result.append(currentLine).append('\n');
                    currentLine.setLength(0);
                    linePos = 0;
                    i++; // skip \n
                } else {
                    linePos = 0; // carriage return to start of line
                }
            } else if (c == '\n') {
                result.append(currentLine).append('\n');
                currentLine.setLength(0);
                linePos = 0;
            } else {
                if (linePos < currentLine.length()) {
                    currentLine.setCharAt(linePos, c);
                } else {
                    currentLine.append(c);
                }
                linePos++;
            }
        }
        result.append(currentLine);
        return result.toString();
    }

    /**
     * Deduplicates redundant shell prompts caused by terminal redraws or signal interrupts.
     */
    public static String deduplicatePrompts(String text) {
        if (text == null || text.isEmpty()) return "";
        String[] lines = text.split("\n", -1);
        if (lines.length <= 1) return text;

        List<String> result = new ArrayList<>();
        String prevPrompt = null;

        for (int i = 0; i < lines.length; i++) {
            String line = lines[i];
            String trimmed = line.trim();

            // Check multi-line prompt block like Kali's ┌──... followed by └─...
            if (trimmed.startsWith("┌──")) {
                int nextNonEmpty = i + 1;
                while (nextNonEmpty < lines.length && lines[nextNonEmpty].trim().isEmpty()) {
                    nextNonEmpty++;
                }
                if (nextNonEmpty < lines.length && lines[nextNonEmpty].trim().startsWith("└─")) {
                    String fullPrompt = trimmed + "\n" + lines[nextNonEmpty].trim();
                    if (fullPrompt.equals(prevPrompt)) {
                        i = nextNonEmpty;
                        continue;
                    }
                    prevPrompt = fullPrompt;
                    result.add(line);
                    result.add(lines[nextNonEmpty]);
                    i = nextNonEmpty;
                    continue;
                }
            }

            // Check single-line prompt duplicate (e.g. repeated "└─# " or identical prompts)
            boolean isPrompt = isPromptLine(trimmed);
            if (isPrompt) {
                if (trimmed.equals(prevPrompt) || (prevPrompt != null && prevPrompt.endsWith(trimmed))) {
                    continue;
                }
                prevPrompt = trimmed;
            } else if (!trimmed.isEmpty()) {
                prevPrompt = null;
            }

            result.add(line);
        }

        return String.join("\n", result);
    }

    public static boolean isPromptLine(String trimmed) {
        if (trimmed == null || trimmed.isEmpty()) return false;
        return trimmed.startsWith("┌") || trimmed.startsWith("└") || trimmed.contains("㉿")
                || trimmed.equals("└─#") || trimmed.equals("└─$")
                || trimmed.startsWith("└─#") || trimmed.startsWith("└─$")
                || trimmed.startsWith("┌──");
    }

    /**
     * Identifies initial shell connection prompts (e.g. Kali's ┌──... or └─#)
     * so they can be suppressed before the user has typed any command.
     */
    public static boolean isInitialPromptChunk(String text) {
        if (text == null || text.isEmpty()) return false;
        String trimmed = text.trim();
        return isPromptLine(trimmed) || stripRemotePrompts(text).isEmpty();
    }

    /**
     * Identifies pre-execution readline redraw prompt lines (e.g. Kali's "└─#" or "└─$")
     * which are emitted by cooked terminal drivers right before command output.
     */
    public static boolean isPreExecutionPromptLine(String trimmed) {
        if (trimmed == null || trimmed.isEmpty()) return false;
        return trimmed.equals("└─#") || trimmed.equals("└─$")
                || trimmed.startsWith("└─#") || trimmed.startsWith("└─$");
    }

    /**
     * Completely strips remote shell prompts (such as Kali multi-line prompts ┌──... and └─#,
     * standard Linux user@host prompts, and Windows drive prompts) from terminal output
     * so that the terminal display remains purely focused on Burp's structured prompt
     * and clean command output without visual redundancy.
     */
    public static String stripRemotePrompts(String text) {
        if (text == null || text.isEmpty()) return "";

        String[] lines = text.split("\n", -1);
        boolean onlyPrompts = true;
        for (String line : lines) {
            String trimmed = line.trim();
            if (trimmed.isEmpty()) continue;
            if (!isPromptLine(trimmed)) {
                onlyPrompts = false;
                break;
            }
        }
        if (onlyPrompts) {
            return "";
        }

        // Find the index of the last non-prompt line
        int lastNonPromptLine = -1;
        for (int i = lines.length - 1; i >= 0; i--) {
            String trimmed = lines[i].trim();
            if (trimmed.isEmpty()) continue;
            if (!isPromptLine(trimmed)) {
                lastNonPromptLine = i;
                break;
            }
        }

        if (lastNonPromptLine == -1) {
            return "";
        }

        // Find the index of the first non-prompt line
        int firstNonPromptLine = 0;
        while (firstNonPromptLine <= lastNonPromptLine) {
            String trimmed = lines[firstNonPromptLine].trim();
            if (trimmed.isEmpty() || isPromptLine(trimmed)) {
                firstNonPromptLine++;
            } else {
                break;
            }
        }

        if (firstNonPromptLine > lastNonPromptLine) {
            return "";
        }

        StringBuilder sb = new StringBuilder();
        for (int i = firstNonPromptLine; i <= lastNonPromptLine; i++) {
            sb.append(lines[i]);
            if (i < lastNonPromptLine || text.contains(lines[i] + "\n")) {
                sb.append("\n");
            }
        }

        return sb.toString();
    }

    /**
     * Suppresses remote shell command echo and stray pre-execution prompts across TCP packets
     * so the terminal display remains unified, clean, and free of stray prompt fragments.
     */
    public synchronized String suppressCommandEcho(String text) {
        if (text == null || text.isEmpty()) return text;
        String s = text;

        // 1. Strip command echo if pending
        if (pendingEchoCommand != null && !pendingEchoCommand.isEmpty()) {
            String cmd = pendingEchoCommand;
            int start = 0;
            while (start < s.length() && (s.charAt(start) == '\r' || s.charAt(start) == '\n' || s.charAt(start) == ' ')) {
                start++;
            }
            String rest = s.substring(start);

            if (rest.startsWith(cmd)) {
                pendingEchoCommand = null;
                int afterCmd = start + cmd.length();
                while (afterCmd < s.length() && (s.charAt(afterCmd) == ' ' || s.charAt(afterCmd) == '\t' || s.charAt(afterCmd) == '\r')) {
                    afterCmd++;
                }
                if (afterCmd < s.length() && s.charAt(afterCmd) == '\n') {
                    afterCmd++;
                }
                s = s.substring(afterCmd);
            } else {
                // Check if chunk has the command on the first line
                int nl = s.indexOf('\n');
                if (nl != -1) {
                    String firstLine = s.substring(0, nl).trim();
                    if (firstLine.equals(cmd)) {
                        pendingEchoCommand = null;
                        s = s.substring(nl + 1);
                    }
                }
            }
        }

        // 2. Strip stray pre-execution prompt lines (like "└─# ") or blank lines across TCP packet boundaries
        if (awaitingCommandOutput) {
            while (!s.isEmpty()) {
                int nl = s.indexOf('\n');
                String line = (nl != -1) ? s.substring(0, nl) : s;
                String trimmed = line.trim();

                // Blank line before command output: strip
                if (trimmed.isEmpty()) {
                    s = (nl != -1) ? s.substring(nl + 1) : "";
                    continue;
                }

                // Pre-execution prompt line (like "└─#" or "└─$"): strip
                if (isPreExecutionPromptLine(trimmed)) {
                    s = (nl != -1) ? s.substring(nl + 1) : "";
                    continue;
                }

                // Non-stray line encountered: command output has arrived or command produced no output and new full prompt arrived
                awaitingCommandOutput = false;
                pendingEchoCommand = null;
                break;
            }
        } else if (pendingEchoCommand != null && !s.trim().isEmpty()) {
            // Non-empty output arrived that was not command echo: clear pending command
            pendingEchoCommand = null;
        }

        return s;
    }

    /**
     * Deduplicates prompts across separate incoming TCP packets.
     */
    public synchronized String filterCrossChunkPrompts(String text) {
        if (text == null || text.isEmpty()) return "";

        String s = text;

        if (lastOutputWasPrompt && lastAppendedPrompt != null) {
            String trimmed = s.trim();

            // If the entire chunk is just a repetition of the last prompt or prompt symbol
            if (trimmed.equals(lastAppendedPrompt) ||
                    (lastAppendedPrompt.contains("└─") && (trimmed.equals("└─#") || trimmed.equals("└─$") || trimmed.startsWith("└─#") || trimmed.startsWith("└─$")))) {
                return "";
            }

            // If chunk starts with Kali multi-line prompt that matches lastAppendedPrompt
            if (trimmed.startsWith("┌──")) {
                int nextNl = s.indexOf('\n');
                if (nextNl != -1) {
                    int secondNl = s.indexOf('\n', nextNl + 1);
                    String firstBlock = (secondNl != -1 ? s.substring(0, secondNl) : s).trim();
                    if (firstBlock.equals(lastAppendedPrompt)) {
                        s = (secondNl != -1 ? s.substring(secondNl + 1) : "");
                    }
                }
            } else if (trimmed.startsWith("└─#") || trimmed.startsWith("└─$")) {
                // Leading redundant bottom half of Kali prompt
                int nl = s.indexOf('\n');
                s = (nl != -1 ? s.substring(nl + 1) : "");
            }
        }

        // Update tracking based on the filtered text
        String trailingPrompt = extractTrailingPrompt(s);
        if (trailingPrompt != null) {
            lastOutputWasPrompt = true;
            lastAppendedPrompt = trailingPrompt;
        } else if (!s.trim().isEmpty()) {
            lastOutputWasPrompt = false;
            lastAppendedPrompt = null;
        }

        return s;
    }

    /**
     * Extracts the trailing prompt from the text if it ends with a prompt.
     */
    public static String extractTrailingPrompt(String text) {
        if (text == null || text.isEmpty()) return null;
        String[] lines = text.split("\n", -1);
        for (int i = lines.length - 1; i >= 0; i--) {
            String line = lines[i].trim();
            if (line.isEmpty()) continue;
            if (line.startsWith("└─") && i > 0) {
                for (int j = i - 1; j >= 0; j--) {
                    String prev = lines[j].trim();
                    if (prev.isEmpty()) continue;
                    if (prev.startsWith("┌──")) {
                        return prev + "\n" + line;
                    }
                    break;
                }
                return line;
            }
            if (isPromptLine(line)) {
                return line;
            }
            return null;
        }
        return null;
    }

    /**
     * Passively inspects incoming banner or prompt to detect remote OS without intrusive probes.
     */
    private void detectShellTypePassively(String rawChunk) {
        if (rawChunk == null || rawChunk.isEmpty()) return;

        // Windows PowerShell indicators
        if (rawChunk.contains("Windows PowerShell") ||
                rawChunk.contains("PS ") && (rawChunk.contains(":\\") || rawChunk.contains(">")) ||
                rawChunk.contains("PS>")) {
            shellType = SessionShellType.WINDOWS_PS;
            return;
        }

        // Windows CMD indicators
        if (rawChunk.contains("Microsoft Windows") ||
                rawChunk.matches("(?s).*[A-Za-z]:\\\\[^>\\r\\n]*>.*") ||
                rawChunk.contains("(c) Microsoft Corporation")) {
            shellType = SessionShellType.WINDOWS_CMD;
            return;
        }

        // Linux / UNIX indicators
        if (rawChunk.contains("Linux") ||
                rawChunk.contains("root@") ||
                rawChunk.contains("uid=") ||
                rawChunk.contains("gid=") ||
                rawChunk.contains("/bin/") ||
                rawChunk.contains("~$") ||
                rawChunk.contains("~#") ||
                rawChunk.contains("┌──") ||
                rawChunk.contains("└─#") ||
                rawChunk.matches("(?s).*[\\w.-]+@[\\w.-]+:.*[$#]\\s*.*")) {
            shellType = SessionShellType.UNIX;
        }
    }

    /**
     * Passively extracts current remote working directory from standard shell prompts.
     */
    private void updateRemotePathPassively(String rawChunk) {
        if (rawChunk == null || rawChunk.isEmpty()) return;

        String detectedPath = null;
        // Kali / bash prompt pattern: e.g. -[~] or -[/var/www/html]
        Matcher mUnix = PATTERN_UNIX_PATH.matcher(rawChunk.trim());
        if (mUnix.find()) {
            detectedPath = mUnix.group(1);
        } else {
            // Windows prompt pattern: C:\path> or PS C:\path>
            Matcher mWin = PATTERN_WIN_PATH.matcher(rawChunk);
            if (mWin.find()) {
                detectedPath = mWin.group(1);
            } else {
                // Standard user@host:path$ or user@host:path#
                Matcher mStd = PATTERN_STD_UNIX_PATH.matcher(rawChunk.trim());
                if (mStd.find()) {
                    detectedPath = mStd.group(1);
                }
            }
        }

        if (detectedPath != null && !detectedPath.equals(currentRemotePath)) {
            currentRemotePath = detectedPath;
            if (listener != null) listener.onPathUpdated(this, currentRemotePath);
        }
    }

    public void sendCommand(String cmd, ExecutorService executor) {
        if (!active || writer == null) return;
        commandHistory.add(cmd);
        historyIndex = commandHistory.size();

        if (cmd.equalsIgnoreCase("clear") || cmd.equalsIgnoreCase("cls")) {
            clearTerminal();
            return;
        }

        appendOutput("\n[" + remoteAddress + "] [DIR: ", styleInput);
        appendOutput(currentRemotePath, stylePath);
        appendOutput("] $ " + cmd + "\n", styleInput);

        lastCommand = cmd;
        pendingEchoCommand = cmd.trim();
        awaitingCommandOutput = true;
        lastOutputWasPrompt = false;
        lastAppendedPrompt = null;
        final String finalCmd = cmd;

        executor.submit(() -> {
            try {
                writeCommand(finalCmd);
            } catch (Exception e) {
                appendOutput("\n[ERROR SENDING COMMAND: " + e.getMessage() + "]\n", styleStatus);
            }
        });
    }

    public void clearTerminal() {
        displayPane.setText("");
        lastOutputWasPrompt = false;
        lastAppendedPrompt = null;
        pendingEchoCommand = null;
        awaitingCommandOutput = false;
        pendingResidual = "";
    }

    public synchronized String getPreviousHistoryCommand() {
        if (commandHistory.isEmpty()) return null;
        if (historyIndex > 0) {
            historyIndex--;
        } else if (historyIndex == -1) {
            historyIndex = commandHistory.size() - 1;
        }
        return commandHistory.get(historyIndex);
    }

    public synchronized String getNextHistoryCommand() {
        if (commandHistory.isEmpty()) return null;
        if (historyIndex < commandHistory.size() - 1) {
            historyIndex++;
            return commandHistory.get(historyIndex);
        } else {
            historyIndex = commandHistory.size();
            return "";
        }
    }

    public synchronized void writeCommand(String cmd) throws IOException {
        if (writer != null) {
            writer.write(cmd);
            if (!cmd.endsWith("\n") && !cmd.endsWith("\r\n")) {
                if (shellType == SessionShellType.WINDOWS_CMD || shellType == SessionShellType.WINDOWS_PS) {
                    writer.write("\r\n");
                } else {
                    writer.write("\n");
                }
            }
            writer.flush();
        }
    }

    public void sendSignalCtrlC(ExecutorService executor) {
        if (!active || writer == null) return;
        executor.submit(() -> {
            try {
                if (writer != null) {
                    writer.write("\u0003");
                    writer.flush();
                }
            } catch (Exception ignored) {}
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
                    writeCommand("powershell -c \"" + psCmd + "\"");
                } else {
                    // Linux echo base64 decode
                    writeCommand("echo '" + base64Content + "' | base64 -d > '" + remoteTargetPath + "'");
                }
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
        if (text == null || text.isEmpty()) return;
        SwingUtilities.invokeLater(() -> {
            try {
                String toInsert = text;
                int docLen = doc.getLength();
                if (docLen > 0 && toInsert.startsWith("\n")) {
                    String endText = doc.getText(Math.max(0, docLen - 2), Math.min(2, docLen));
                    if (endText.endsWith("\n\n")) {
                        while (toInsert.startsWith("\n")) {
                            toInsert = toInsert.substring(1);
                        }
                    } else if (endText.endsWith("\n") && toInsert.startsWith("\n\n")) {
                        toInsert = toInsert.substring(1);
                    }
                }
                if (!toInsert.isEmpty()) {
                    doc.insertString(doc.getLength(), toInsert, style);
                    displayPane.setCaretPosition(doc.getLength());
                }
            } catch (Exception ignored) {}
        });
    }

    public void close() {
        if (!active) return;
        active = false;
        if (closedAt == null) {
            closedAt = LocalDateTime.now();
        }
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
        LocalDateTime end = (!active && closedAt != null) ? closedAt : LocalDateTime.now();
        Duration duration = Duration.between(connectedAt, end);
        long seconds = Math.max(0, duration.getSeconds());
        long hours = seconds / 3600;
        long minutes = (seconds % 3600) / 60;
        long secs = seconds % 60;
        if (hours > 0) {
            return String.format("%dh %dm %ds", hours, minutes, secs);
        }
        return String.format("%dm %ds", minutes, secs);
    }

    public LocalDateTime getClosedAt() { return closedAt; }

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
