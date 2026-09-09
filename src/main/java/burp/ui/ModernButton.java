package burp.ui;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

/**
 * Modern flat button with smooth hover feedback and crisp typography.
 * Strictly icon-free, focusing on clean geometry and color semantics.
 */
public class ModernButton extends JButton {

    private final Color normalBg;
    private final Color hoverBg;
    private final Color pressedBg;
    private final Color disabledBg;
    private final int radius;

    public ModernButton(String text, Color baseColor) {
        this(text, baseColor, 6);
    }

    public ModernButton(String text, Color baseColor, int radius) {
        super(text);
        this.normalBg = baseColor;
        this.hoverBg = computeHoverColor(baseColor);
        this.pressedBg = computePressedColor(baseColor);
        this.disabledBg = new Color(226, 232, 240); // Soft gray
        this.radius = radius;

        setFont(UITheme.FONT_BOLD);
        setForeground(Color.WHITE);
        setBackground(normalBg);
        setFocusPainted(false);
        setBorderPainted(false);
        setContentAreaFilled(false);
        setOpaque(false);
        setCursor(new Cursor(Cursor.HAND_CURSOR));
        setBorder(new EmptyBorder(6, 14, 6, 14));

        addMouseListener(new MouseAdapter() {
            @Override
            public void mouseEntered(MouseEvent e) {
                if (isEnabled()) {
                    repaint();
                }
            }

            @Override
            public void mouseExited(MouseEvent e) {
                if (isEnabled()) {
                    repaint();
                }
            }

            @Override
            public void mousePressed(MouseEvent e) {
                if (isEnabled()) {
                    repaint();
                }
            }

            @Override
            public void mouseReleased(MouseEvent e) {
                if (isEnabled()) {
                    repaint();
                }
            }
        });
    }

    private Color computeHoverColor(Color c) {
        int r = Math.max(0, (int) (c.getRed() * 0.88));
        int g = Math.max(0, (int) (c.getGreen() * 0.88));
        int b = Math.max(0, (int) (c.getBlue() * 0.88));
        return new Color(r, g, b);
    }

    private Color computePressedColor(Color c) {
        int r = Math.max(0, (int) (c.getRed() * 0.75));
        int g = Math.max(0, (int) (c.getGreen() * 0.75));
        int b = Math.max(0, (int) (c.getBlue() * 0.75));
        return new Color(r, g, b);
    }

    @Override
    protected void paintComponent(Graphics g) {
        Graphics2D g2 = (Graphics2D) g.create();
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

        if (!isEnabled()) {
            g2.setColor(disabledBg);
            setForeground(new Color(148, 163, 184));
        } else if (getModel().isPressed()) {
            g2.setColor(pressedBg);
            setForeground(Color.WHITE);
        } else if (getModel().isRollover()) {
            g2.setColor(hoverBg);
            setForeground(Color.WHITE);
        } else {
            g2.setColor(normalBg);
            setForeground(Color.WHITE);
        }

        g2.fillRoundRect(0, 0, getWidth(), getHeight(), radius, radius);
        g2.dispose();

        super.paintComponent(g);
    }
}
