package burp.ui;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.LineBorder;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

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

    // --- Theme Change Listeners Registry ---
    private static final List<Runnable> themeChangeListeners = new CopyOnWriteArrayList<>();

    static {
        try {
            UIManager.addPropertyChangeListener(evt -> {
                if ("lookAndFeel".equals(evt.getPropertyName())) {
                    fireThemeChanged();
                }
            });
        } catch (Exception ignored) {}
    }

    public static void addThemeChangeListener(Runnable listener) {
        if (listener != null) {
            themeChangeListeners.add(listener);
        }
    }

    public static void removeThemeChangeListener(Runnable listener) {
        if (listener != null) {
            themeChangeListeners.remove(listener);
        }
    }

    public static void fireThemeChanged() {
        for (Runnable r : themeChangeListeners) {
            try {
                r.run();
            } catch (Exception ignored) {}
        }
    }

    /**
     * Determines if the current Look and Feel or Burp Suite environment is in Dark Mode.
     */
    public static boolean isDarkMode() {
        Object flatLafDark = UIManager.get("laf.dark");
        if (flatLafDark instanceof Boolean) {
            return (Boolean) flatLafDark;
        }

        LookAndFeel laf = UIManager.getLookAndFeel();
        if (laf != null) {
            String name = (laf.getName() + " " + laf.getID() + " " + laf.getClass().getName()).toLowerCase();
            if (name.contains("dark") || name.contains("darcula")) {
                return true;
            }
        }

        Color bg = UIManager.getColor("Panel.background");
        if (bg == null) {
            bg = UIManager.getColor("control");
        }
        if (bg != null) {
            double luminance = (0.299 * bg.getRed() + 0.587 * bg.getGreen() + 0.114 * bg.getBlue());
            return luminance < 128.0;
        }

        Color fg = UIManager.getColor("Label.foreground");
        if (fg == null) {
            fg = UIManager.getColor("textText");
        }
        if (fg != null) {
            double fgLuminance = (0.299 * fg.getRed() + 0.587 * fg.getGreen() + 0.114 * fg.getBlue());
            if (fgLuminance > 180.0) {
                return true;
            }
        }

        return false;
    }

    // --- Dynamic Theme-Aware Getters ---

    public static Color getPrimaryBg() {
        return isDarkMode() ? new Color(22, 27, 34) : PRIMARY_BG;
    }

    public static Color getCardBg() {
        return isDarkMode() ? new Color(30, 36, 46) : CARD_BG;
    }

    public static Color getCardHeaderBg() {
        return isDarkMode() ? new Color(38, 44, 54) : CARD_HEADER_BG;
    }

    public static Color getBorderColor() {
        return isDarkMode() ? new Color(54, 62, 74) : BORDER_LIGHT;
    }

    public static Color getTextPrimary() {
        return isDarkMode() ? new Color(240, 246, 252) : TEXT_PRIMARY;
    }

    public static Color getTextSecondary() {
        return isDarkMode() ? new Color(148, 163, 184) : TEXT_SECONDARY;
    }

    public static Color getTextMuted() {
        return isDarkMode() ? new Color(100, 116, 139) : TEXT_MUTED;
    }

    public static Color getDisabledButtonBg() {
        return isDarkMode() ? new Color(45, 52, 64) : new Color(226, 232, 240);
    }

    public static Color getDisabledButtonFg() {
        return isDarkMode() ? new Color(100, 116, 139) : new Color(148, 163, 184);
    }

    public static Color getTableGridColor() {
        return isDarkMode() ? new Color(48, 54, 64) : BORDER_LIGHT;
    }

    /**
     * Creates an elegant border for cards and control sections.
     */
    public static Border createCardBorder() {
        return new CompoundBorder(
                new LineBorder(getBorderColor(), 1, true),
                new EmptyBorder(10, 14, 10, 14)
        );
    }

    /**
     * Creates a modern titled border matching the current theme.
     */
    public static Border createTitledCardBorder(String title) {
        return new CompoundBorder(
                new TitledBorder(new LineBorder(getBorderColor(), 1), title, TitledBorder.LEFT, TitledBorder.TOP, FONT_SUBTITLE, getTextSecondary()),
                new EmptyBorder(4, 4, 4, 4)
        );
    }

    /**
     * Creates an elegant bordered section with padding.
     */
    public static Border createSectionBorder(int top, int left, int bottom, int right) {
        return new CompoundBorder(
                new LineBorder(getBorderColor(), 1, false),
                new EmptyBorder(top, left, bottom, right)
        );
    }

    /**
     * Creates a consistent table cell renderer that suppresses single-cell focus borders.
     */
    public static javax.swing.table.TableCellRenderer createTableCellRenderer() {
        return new javax.swing.table.DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value,
                                                           boolean isSelected, boolean hasFocus, int row, int column) {
                // Pass hasFocus = false to prevent Swing's inconsistent single-cell focus border
                super.getTableCellRendererComponent(table, value, isSelected, false, row, column);
                setBorder(new EmptyBorder(3, 8, 3, 8));
                return this;
            }
        };
    }

    /**
     * Applies uniform, clean styling and cell renderers across all table columns.
     */
    public static void styleTable(JTable table) {
        table.setFont(FONT_CODE);
        table.getTableHeader().setFont(FONT_SUBTITLE);
        table.setRowHeight(24);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setShowGrid(true);
        table.setShowHorizontalLines(true);
        table.setShowVerticalLines(true);
        table.setIntercellSpacing(new Dimension(1, 1));
        table.setGridColor(getTableGridColor());

        Color tableBg = isDarkMode() ? getCardBg() : Color.WHITE;
        Color tableFg = getTextPrimary();
        table.setBackground(tableBg);
        table.setForeground(tableFg);

        javax.swing.table.TableCellRenderer renderer = createTableCellRenderer();
        for (int i = 0; i < table.getColumnModel().getColumnCount(); i++) {
            table.getColumnModel().getColumn(i).setCellRenderer(renderer);
        }
    }

    /**
     * Styles a standard JTextField for a clean, minimal appearance.
     */
    public static void styleTextField(JTextField field) {
        field.setFont(FONT_BODY);
        field.setBorder(new CompoundBorder(
                new LineBorder(getBorderColor(), 1, true),
                new EmptyBorder(4, 8, 4, 8)
        ));
        Color bg = UIManager.getColor("TextField.background");
        Color fg = UIManager.getColor("TextField.foreground");
        if (bg == null) bg = isDarkMode() ? new Color(22, 27, 34) : Color.WHITE;
        if (fg == null) fg = getTextPrimary();
        field.setBackground(bg);
        field.setForeground(fg);
        field.setCaretColor(fg);
    }

    /**
     * Styles a JComboBox for clean modern look.
     */
    public static void styleComboBox(JComboBox<?> combo) {
        combo.setFont(FONT_BODY);
        Color bg = UIManager.getColor("ComboBox.background");
        Color fg = UIManager.getColor("ComboBox.foreground");
        if (bg == null) bg = isDarkMode() ? new Color(30, 36, 46) : Color.WHITE;
        if (fg == null) fg = getTextPrimary();
        combo.setBackground(bg);
        combo.setForeground(fg);
    }
}
