package burp.ui;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

/**
 * An interactive, modern rounded pill chip displaying an IP:Port listening address.
 * Strictly icon-free, providing clear text feedback upon clicking ("COPIED").
 */
public class AddressChip extends JPanel {

    private final String displayText;
    private final String copyValue;
    private final JLabel label;
    private boolean isCopied = false;
    private boolean isHovered = false;

    private static final Color BG_NORMAL = new Color(241, 245, 249);      // #f1f5f9
    private static final Color BG_HOVER = new Color(226, 232, 240);       // #e2e8f0
    private static final Color BG_COPIED = new Color(220, 252, 231);      // #dcfce7
    private static final Color BORDER_NORMAL = new Color(203, 213, 225);  // #cbd5e1
    private static final Color BORDER_HOVER = new Color(148, 163, 184);   // #94a3b8
    private static final Color BORDER_COPIED = new Color(74, 222, 128);   // #4ade80
    private static final Color FG_NORMAL = new Color(30, 41, 59);         // #1e293b
    private static final Color FG_COPIED = new Color(22, 101, 52);        // #166534

    // Dark Mode Colors
    private static final Color DARK_BG_NORMAL = new Color(33, 38, 45);
    private static final Color DARK_BG_HOVER = new Color(48, 54, 61);
    private static final Color DARK_BG_COPIED = new Color(22, 54, 34);
    private static final Color DARK_BORDER_NORMAL = new Color(56, 64, 75);
    private static final Color DARK_BORDER_HOVER = new Color(88, 100, 118);
    private static final Color DARK_BORDER_COPIED = new Color(46, 160, 67);
    private static final Color DARK_FG_NORMAL = new Color(230, 237, 243);
    private static final Color DARK_FG_COPIED = new Color(63, 185, 80);

    public AddressChip(String text) {
        this(text, text);
    }

    public AddressChip(String displayText, String copyValue) {
        super(new FlowLayout(FlowLayout.CENTER, 8, 3));
        this.displayText = displayText;
        this.copyValue = (copyValue != null && !copyValue.isEmpty()) ? copyValue : displayText;
        setOpaque(false);
        setCursor(new Cursor(Cursor.HAND_CURSOR));
        setToolTipText("Click to copy: " + this.copyValue);
        setBorder(new EmptyBorder(1, 4, 1, 4));

        label = new JLabel(displayText);
        label.setFont(UITheme.FONT_CODE_BOLD);
        label.setForeground(getNormalFg());
        label.setCursor(new Cursor(Cursor.HAND_CURSOR));
        add(label);

        MouseAdapter adapter = new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                if (SwingUtilities.isLeftMouseButton(e)) {
                    copyToClipboard(e);
                }
            }

            @Override
            public void mouseEntered(MouseEvent e) {
                isHovered = true;
                repaint();
            }

            @Override
            public void mouseExited(MouseEvent e) {
                isHovered = false;
                repaint();
            }
        };

        addMouseListener(adapter);
        label.addMouseListener(adapter);
    }

    @Override
    public void updateUI() {
        super.updateUI();
        if (label != null && !isCopied) {
            label.setForeground(getNormalFg());
        }
        repaint();
    }

    public void refreshTheme() {
        if (label != null && !isCopied) {
            label.setForeground(getNormalFg());
        }
        repaint();
    }

    private Color getNormalBg() {
        return UITheme.isDarkMode() ? DARK_BG_NORMAL : BG_NORMAL;
    }

    private Color getHoverBg() {
        return UITheme.isDarkMode() ? DARK_BG_HOVER : BG_HOVER;
    }

    private Color getCopiedBg() {
        return UITheme.isDarkMode() ? DARK_BG_COPIED : BG_COPIED;
    }

    private Color getNormalBorder() {
        return UITheme.isDarkMode() ? DARK_BORDER_NORMAL : BORDER_NORMAL;
    }

    private Color getHoverBorder() {
        return UITheme.isDarkMode() ? DARK_BORDER_HOVER : BORDER_HOVER;
    }

    private Color getCopiedBorder() {
        return UITheme.isDarkMode() ? DARK_BORDER_COPIED : BORDER_COPIED;
    }

    private Color getNormalFg() {
        return UITheme.isDarkMode() ? DARK_FG_NORMAL : FG_NORMAL;
    }

    private Color getCopiedFg() {
        return UITheme.isDarkMode() ? DARK_FG_COPIED : FG_COPIED;
    }

    private void copyToClipboard(MouseEvent e) {
        try {
            if (!GraphicsEnvironment.isHeadless()) {
                StringSelection selection = new StringSelection(copyValue);
                Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
                if (clipboard != null) {
                    clipboard.setContents(selection, null);
                }
            }
        } catch (HeadlessException | IllegalStateException | SecurityException ignored) {
            // In headless CI or environments without clipboard access, fail gracefully
        } catch (Throwable ignored) {
            // Guard against any other unexpected environment-specific clipboard exception
        }

        isCopied = true;
        label.setText("COPIED: " + copyValue);
        label.setForeground(getCopiedFg());
        repaint();

        // Toast feedback without icons
        showToast(e);

        Timer timer = new Timer(1500, evt -> {
            isCopied = false;
            label.setText(displayText);
            label.setForeground(getNormalFg());
            repaint();
        });
        timer.setRepeats(false);
        timer.start();
    }

    private void showToast(MouseEvent e) {
        if (GraphicsEnvironment.isHeadless()) {
            return;
        }
        Window window = SwingUtilities.getWindowAncestor(this);
        if (window == null) return;

        try {
            JWindow toast = new JWindow(window);
            JPanel toastPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 6));
            toastPanel.setBackground(UITheme.STATUS_SUCCESS);
            toastPanel.setBorder(new EmptyBorder(4, 10, 4, 10));

            JLabel msg = new JLabel("Copied to clipboard: " + copyValue);
            msg.setFont(UITheme.FONT_BOLD);
            msg.setForeground(Color.WHITE);
            toastPanel.add(msg);

            toast.getContentPane().add(toastPanel);
            toast.pack();

            Point pt = e.getLocationOnScreen();
            toast.setLocation(pt.x + 8, Math.max(0, pt.y - toast.getHeight() - 4));
            toast.setFocusableWindowState(false);
            toast.setVisible(true);

            Timer t = new Timer(1400, evt -> toast.dispose());
            t.setRepeats(false);
            t.start();
        } catch (Exception ignored) {}
    }

    @Override
    protected void paintComponent(Graphics g) {
        Graphics2D g2 = (Graphics2D) g.create();
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

        int w = getWidth() - 1;
        int h = getHeight() - 1;
        int arc = 12;

        if (isCopied) {
            g2.setColor(getCopiedBg());
            g2.fillRoundRect(0, 0, w, h, arc, arc);
            g2.setColor(getCopiedBorder());
            g2.setStroke(new BasicStroke(1.2f));
            g2.drawRoundRect(0, 0, w, h, arc, arc);
            label.setForeground(getCopiedFg());
        } else if (isHovered) {
            g2.setColor(getHoverBg());
            g2.fillRoundRect(0, 0, w, h, arc, arc);
            g2.setColor(getHoverBorder());
            g2.setStroke(new BasicStroke(1.2f));
            g2.drawRoundRect(0, 0, w, h, arc, arc);
            label.setForeground(getNormalFg());
        } else {
            g2.setColor(getNormalBg());
            g2.fillRoundRect(0, 0, w, h, arc, arc);
            g2.setColor(getNormalBorder());
            g2.setStroke(new BasicStroke(1.0f));
            g2.drawRoundRect(0, 0, w, h, arc, arc);
            label.setForeground(getNormalFg());
        }

        g2.dispose();
        super.paintComponent(g);
    }
}
