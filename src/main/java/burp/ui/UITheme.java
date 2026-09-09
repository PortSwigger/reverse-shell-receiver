package burp.ui;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.LineBorder;
import java.awt.*;

/**
 * Clean, modern, and elegant UI theme constants and styling utilities.
 * Strictly free of icons and emojis for a refined, minimalist aesthetic.
 */
public final class UITheme {

    private UITheme() {}

    // --- Modern Color Palette ---
    public static final Color PRIMARY_BG = new Color(248, 250, 252);        // #f8fafc
    public static final Color CARD_BG = new Color(255, 255, 255);           // #ffffff
    public static final Color CARD_HEADER_BG = new Color(241, 245, 249);    // #f1f5f9
    public static final Color DARK_PANEL_BG = new Color(15, 20, 28);        // #0f141c
    public static final Color DARK_INPUT_BG = new Color(22, 27, 34);        // #161b22
    public static final Color BORDER_LIGHT = new Color(226, 232, 240);      // #e2e8f0
    public static final Color BORDER_DARK = new Color(48, 54, 61);          // #30363d
    public static final Color DIVIDER_COLOR = new Color(226, 232, 240);    // #e2e8f0

    // --- Text Colors ---
    public static final Color TEXT_PRIMARY = new Color(15, 23, 42);         // #0f172a
    public static final Color TEXT_SECONDARY = new Color(100, 116, 139);    // #64748b
    public static final Color TEXT_MUTED = new Color(148, 163, 184);        // #94a3b8
    public static final Color TEXT_DARK_PRIMARY = new Color(241, 245, 249);  // #f1f5f9
    public static final Color TEXT_DARK_MUTED = new Color(139, 148, 158);   // #8b949e

    // --- Semantic Status Colors ---
    public static final Color STATUS_SUCCESS = new Color(16, 185, 129);     // Emerald #10b981
    public static final Color STATUS_DANGER = new Color(239, 68, 68);       // Ruby #ef4444
    public static final Color STATUS_INFO = new Color(37, 99, 235);         // Slate Blue #2563eb
    public static final Color STATUS_WARNING = new Color(217, 119, 6);      // Amber #d97706
    public static final Color STATUS_ACCENT = new Color(6, 182, 212);       // Cyan Teal #06b6d4

    // --- Terminal Styles ---
    public static final Color TERM_BG = new Color(13, 17, 23);             // Deep Obsidian #0d1117
    public static final Color TERM_FG = new Color(230, 237, 243);          // #e6edf3
    public static final Color TERM_PROMPT = new Color(88, 166, 255);       // #58a6ff
    public static final Color TERM_PATH = new Color(227, 179, 65);          // #e3b341
    public static final Color TERM_STATUS = new Color(63, 185, 80);         // #3fb950
    public static final Color TERM_OUTPUT = new Color(240, 246, 252);       // #f0f6fc

    // --- Fonts ---
    public static final Font FONT_TITLE = new Font("Segoe UI", Font.BOLD, 13);
    public static final Font FONT_SUBTITLE = new Font("Segoe UI", Font.BOLD, 11);
    public static final Font FONT_BODY = new Font("Segoe UI", Font.PLAIN, 12);
    public static final Font FONT_BOLD = new Font("Segoe UI", Font.BOLD, 12);
    public static final Font FONT_SMALL = new Font("Segoe UI", Font.PLAIN, 11);
    public static final Font FONT_CODE = new Font("Consolas", Font.PLAIN, 12);
    public static final Font FONT_CODE_BOLD = new Font("Consolas", Font.BOLD, 12);
    public static final Font FONT_BADGE = new Font("Segoe UI", Font.BOLD, 10);

    /**
     * Creates an elegant border for cards and control sections.
     */
    public static Border createCardBorder() {
        return new CompoundBorder(
                new LineBorder(BORDER_LIGHT, 1, true),
                new EmptyBorder(10, 14, 10, 14)
        );
    }

    /**
     * Creates an elegant bordered section with padding.
     */
    public static Border createSectionBorder(int top, int left, int bottom, int right) {
        return new CompoundBorder(
                new LineBorder(BORDER_LIGHT, 1, false),
                new EmptyBorder(top, left, bottom, right)
        );
    }

    /**
     * Styles a standard JTextField for a clean, minimal appearance.
     */
    public static void styleTextField(JTextField field) {
        field.setFont(FONT_BODY);
        field.setBorder(new CompoundBorder(
                new LineBorder(BORDER_LIGHT, 1, true),
                new EmptyBorder(4, 8, 4, 8)
        ));
        field.setBackground(Color.WHITE);
        field.setForeground(TEXT_PRIMARY);
    }

    /**
     * Styles a JComboBox for clean modern look.
     */
    public static void styleComboBox(JComboBox<?> combo) {
        combo.setFont(FONT_BODY);
        combo.setBackground(Color.WHITE);
        combo.setForeground(TEXT_PRIMARY);
    }
}
