package burp;

import javax.swing.*;
import java.awt.*;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

public class BurpExtender implements IBurpExtender, ITab, IContextMenuFactory, IExtensionStateListener {

    private IBurpExtenderCallbacks callbacks;
    private ReverseShellReceiverPanel reverseShellReceiverPanel;
    private PrintWriter stdout;
    private PrintWriter stderr;
    private boolean isUnloading = false;

    private static class TeeOutputStream extends OutputStream {
        private final OutputStream streamOne;
        private final OutputStream streamTwo;

        public TeeOutputStream(OutputStream streamOne, OutputStream streamTwo) {
            this.streamOne = streamOne;
            this.streamTwo = streamTwo;
        }

        @Override
        public void write(int b) throws IOException {
            streamOne.write(b);
            streamTwo.write(b);
        }

        @Override
        public void flush() throws IOException {
            streamOne.flush();
            streamTwo.flush();
        }

        @Override
        public void close() throws IOException {
            try {
                streamOne.close();
            } finally {
                streamTwo.close();
            }
        }
    }

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.stdout = new PrintWriter(callbacks.getStdout(), true);

        OutputStream dualErrorStream = new TeeOutputStream(callbacks.getStderr(), System.err);
        this.stderr = new PrintWriter(dualErrorStream, true);

        callbacks.setExtensionName("Reverse Shell Receiver");

        // Initialize Reverse Shell Receiver panel
        reverseShellReceiverPanel = new ReverseShellReceiverPanel(callbacks);

        callbacks.registerContextMenuFactory(this);
        callbacks.registerExtensionStateListener(this);

        SwingUtilities.invokeLater(() -> {
            callbacks.customizeUiComponent(reverseShellReceiverPanel);
            callbacks.addSuiteTab(this);
            loadAllSettings();
            stdout.println("Reverse Shell Receiver loaded successfully!");
        });
    }

    private void saveAllSettings(boolean showMessage) {
        try {
            if (reverseShellReceiverPanel != null) {
                reverseShellReceiverPanel.saveSettings(showMessage);
            }
            if (showMessage) {
                stdout.println("Reverse Shell Receiver settings saved successfully!");
            }
        } catch (Exception e) {
            stderr.println("Error saving Reverse Shell Receiver settings: " + e.getMessage());
            e.printStackTrace(stderr);
        }
    }

    private void loadAllSettings() {
        try {
            if (reverseShellReceiverPanel != null) {
                reverseShellReceiverPanel.loadSettings();
            }
            stdout.println("Reverse Shell Receiver settings loaded successfully!");
        } catch (Exception e) {
            stderr.println("Error loading Reverse Shell Receiver settings: " + e.getMessage());
            e.printStackTrace(stderr);
        }
    }

    @Override
    public void extensionUnloaded() {
        stdout.println("Reverse Shell Receiver extension unloading.");
        isUnloading = true;
        if (reverseShellReceiverPanel != null) {
            reverseShellReceiverPanel.cleanup();
        }
        saveAllSettings(false);
    }

    @Override
    public String getTabCaption() {
        return "Reverse Shell Receiver";
    }

    @Override
    public Component getUiComponent() {
        return reverseShellReceiverPanel;
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        int ctx = invocation.getInvocationContext();
        if (ctx != IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST &&
                ctx != IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_RESPONSE &&
                ctx != IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST &&
                ctx != IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE &&
                ctx != IContextMenuInvocation.CONTEXT_PROXY_HISTORY &&
                ctx != IContextMenuInvocation.CONTEXT_TARGET_SITE_MAP_TABLE) {
            return null;
        }
        List<JMenuItem> menu = new ArrayList<>();
        JMenuItem sendToReverseShellReceiver = new JMenuItem("Send to Reverse Shell Receiver");
        sendToReverseShellReceiver.addActionListener(e -> {
            IHttpRequestResponse[] messages = invocation.getSelectedMessages();
            if (messages == null) return;
            int toolFlag = invocation.getToolFlag();
            for (IHttpRequestResponse requestResponse : messages) {
                reverseShellReceiverPanel.addEntry(requestResponse, toolFlag);
            }
        });
        menu.add(sendToReverseShellReceiver);
        return menu;
    }
}