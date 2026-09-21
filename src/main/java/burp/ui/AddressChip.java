package burp.ui;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
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
        label.setForeground(FG_NORMAL);
        label.setCursor(new Cursor(Cursor.HAND_CURSOR));
        add(label);

        MouseAdapter adapter = new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                copyToClipboard(e);
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

    private void copyToClipboard(MouseEvent e) {
        StringSelection selection = new StringSelection(copyValue);
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(selection, null);

        isCopied = true;
        label.setText("COPIED: " + copyValue);
        label.setForeground(FG_COPIED);
        repaint();

        // Toast feedback without icons
        showToast(e);

        Timer timer = new Timer(1500, evt -> {
            isCopied = false;
            label.setText(displayText);
            label.setForeground(FG_NORMAL);
            repaint();
        });
        timer.setRepeats(false);
        timer.start();
    }

    private void showToast(MouseEvent e) {
        Window window = SwingUtilities.getWindowAncestor(this);
        if (window == null) return;

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
        toast.setLocation(pt.x + 8, pt.y - toast.getHeight() - 4);
        toast.setVisible(true);

        Timer t = new Timer(1400, evt -> toast.dispose());
        t.setRepeats(false);
        t.start();
    }

    @Override
    protected void paintComponent(Graphics g) {
        Graphics2D g2 = (Graphics2D) g.create();
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

        int w = getWidth() - 1;
        int h = getHeight() - 1;
        int arc = 12;

        if (isCopied) {
            g2.setColor(BG_COPIED);
            g2.fillRoundRect(0, 0, w, h, arc, arc);
            g2.setColor(BORDER_COPIED);
            g2.setStroke(new BasicStroke(1.2f));
            g2.drawRoundRect(0, 0, w, h, arc, arc);
        } else if (isHovered) {
            g2.setColor(BG_HOVER);
            g2.fillRoundRect(0, 0, w, h, arc, arc);
            g2.setColor(BORDER_HOVER);
            g2.setStroke(new BasicStroke(1.2f));
            g2.drawRoundRect(0, 0, w, h, arc, arc);
        } else {
            g2.setColor(BG_NORMAL);
            g2.fillRoundRect(0, 0, w, h, arc, arc);
            g2.setColor(BORDER_NORMAL);
            g2.setStroke(new BasicStroke(1.0f));
            g2.drawRoundRect(0, 0, w, h, arc, arc);
        }

        g2.dispose();
        super.paintComponent(g);
    }
}
