package shieldx.ui;

import javax.swing.*;
import javax.swing.text.*;
import javax.swing.text.JTextComponent;
import java.awt.*;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.File;
import java.net.URI;

public class Main {

    static final Color BG_MAIN = new Color(0x0D1117);
    static final Color BG_PANEL = new Color(0x161B22);
    static final Color ACCENT = new Color(0x00E5FF);
    static final Color SUCCESS = new Color(0x2ECC71);
    static final Color ERROR = new Color(0xFF6B6B);
    static final Color INFO = new Color(0x4DA3FF);
    static final Color PLACEHOLDER = new Color(120, 120, 120);

    static JTextPane logPane;
    static JPanel topPanel;

    public static void main(String[] args) {
        SwingUtilities.invokeLater(Main::createUI);
    }

    static void createUI() {
        JFrame frame = new JFrame("ShieldX \"A Cyber Defense Platform\"");
        frame.setSize(1300, 800);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setLayout(new BorderLayout());
        frame.getContentPane().setBackground(BG_MAIN);

        JMenuBar bar = new JMenuBar();
        bar.setBackground(BG_PANEL);

        JMenu file = new JMenu("File");
        JMenuItem exit = new JMenuItem("Exit");
        exit.addActionListener(e -> System.exit(0));
        file.add(exit);

        JMenu view = new JMenu("View");
        JMenuItem clearLogs = new JMenuItem("Clear Logs");
        clearLogs.addActionListener(e -> logPane.setText(""));
        view.add(clearLogs);

        JMenu tools = new JMenu("Tools");
        JMenuItem phishing = new JMenuItem("Phishing");
        phishing.addActionListener(e -> phishingUI());
        JMenuItem misconfig = new JMenuItem("Misconfig");
        misconfig.addActionListener(e -> misconfigUI());
        tools.add(phishing);
        tools.add(misconfig);

        JMenu help = new JMenu("Help");
        JMenuItem about = new JMenuItem("About ShieldX");
        about.addActionListener(e ->
                JOptionPane.showMessageDialog(
                        frame,
                        "ShieldX\n An Enterprise SOC Platform\nVersion 1.0\n 2026\n Developed By JAHANZAIB ASHRAF MIR",
                        "About ShieldX",
                        JOptionPane.INFORMATION_MESSAGE
                )
        );
        help.add(about);

        for (JMenu m : new JMenu[]{file, view, tools, help}) {
            m.setForeground(Color.WHITE);
            bar.add(m);
        }

        frame.setJMenuBar(bar);

        JPanel sidebar = new JPanel(new GridLayout(5, 1, 10, 10));
        sidebar.setPreferredSize(new Dimension(150, 0));
        sidebar.setBackground(BG_PANEL);
        sidebar.setBorder(BorderFactory.createEmptyBorder(20, 10, 20, 10));

        sidebar.add(sidebarButton("Phishing", Main::phishingUI));
        sidebar.add(sidebarButton("Misconfig", Main::misconfigUI));
        sidebar.add(sidebarButton("Zeroday", () -> log("INFO", "Zeroday module selected")));

        frame.add(sidebar, BorderLayout.WEST);

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        split.setResizeWeight(0.65);
        split.setBorder(null);

        topPanel = new JPanel();
        topPanel.setBackground(BG_MAIN);

        split.setTopComponent(topPanel);
        split.setBottomComponent(logPanel());

        frame.add(split, BorderLayout.CENTER);
        frame.setVisible(true);

        log("INFO", "ShieldX initialized");
    }

    static JButton sidebarButton(String text, Runnable action) {
        JButton btn = new JButton(text);
        btn.setBackground(BG_PANEL);
        btn.setForeground(Color.WHITE);
        btn.setFont(new Font("Segoe UI", Font.BOLD, 13));
        btn.setFocusPainted(false);
        btn.addActionListener(e -> action.run());
        return btn;
    }

    static void phishingUI() {
        topPanel.removeAll();
        topPanel.setLayout(new BorderLayout(20, 20));
        topPanel.setBorder(BorderFactory.createEmptyBorder(40, 40, 40, 40));

        JLabel title = new JLabel("Phishing Link Detection");
        title.setForeground(Color.WHITE);
        title.setFont(new Font("Inter", Font.BOLD, 26));

        JTextField urlField = new JTextField("Paste the link here");
        urlField.setForeground(PLACEHOLDER);
        urlField.setBackground(BG_PANEL);
        urlField.setCaretColor(Color.WHITE);
        urlField.setFont(new Font("Inter", Font.PLAIN, 16));
        urlField.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));

        // Right-click paste / copy support
        attachContextMenu(urlField);

        urlField.addFocusListener(new java.awt.event.FocusAdapter() {
            public void focusGained(java.awt.event.FocusEvent e) {
                if (urlField.getText().equals("Paste the link here")) {
                    urlField.setText("");
                    urlField.setForeground(Color.WHITE);
                }
            }
            public void focusLost(java.awt.event.FocusEvent e) {
                if (urlField.getText().isEmpty()) {
                    urlField.setText("Paste the link here");
                    urlField.setForeground(PLACEHOLDER);
                }
            }
        });

        JTextArea output = new JTextArea();
        output.setEditable(false);
        output.setFont(new Font("JetBrains Mono", Font.PLAIN, 13));
        output.setBackground(new Color(10, 14, 18));
        output.setForeground(Color.WHITE);
        attachContextMenu(output);

        JButton scanBtn = new JButton("Run Scan");
        scanBtn.setBackground(ACCENT);
        scanBtn.addActionListener(e -> runPhishingScan(urlField.getText(), output));

        JPanel top = new JPanel(new BorderLayout(10, 10));
        top.setBackground(BG_MAIN);
        top.add(title, BorderLayout.NORTH);
        top.add(urlField, BorderLayout.CENTER);
        top.add(scanBtn, BorderLayout.EAST);

        topPanel.add(top, BorderLayout.NORTH);
        topPanel.add(new JScrollPane(output), BorderLayout.CENTER);
        topPanel.revalidate();
        topPanel.repaint();
    }

    // ---- REST OF FILE UNCHANGED BELOW ----

    static void misconfigUI() {
        topPanel.removeAll();
        topPanel.setLayout(new BorderLayout(20, 20));
        topPanel.setBorder(BorderFactory.createEmptyBorder(40, 40, 40, 40));

        JLabel title = new JLabel("Misconfiguration Detection");
        title.setForeground(Color.WHITE);
        title.setFont(new Font("Inter", Font.BOLD, 26));

        JTextArea output = new JTextArea();
        output.setEditable(false);
        output.setFont(new Font("JetBrains Mono", Font.PLAIN, 13));
        output.setBackground(new Color(10, 14, 18));
        output.setForeground(Color.WHITE);
        attachContextMenu(output);

        JButton scanBtn = new JButton("Run Scan");
        scanBtn.setBackground(ACCENT);
        scanBtn.addActionListener(e -> runMisconfigScan(output));

        JPanel top = new JPanel(new BorderLayout(10, 10));
        top.setBackground(BG_MAIN);
        top.add(title, BorderLayout.NORTH);
        top.add(scanBtn, BorderLayout.EAST);

        topPanel.add(top, BorderLayout.NORTH);
        topPanel.add(new JScrollPane(output), BorderLayout.CENTER);
        topPanel.revalidate();
        topPanel.repaint();
    }

    static void runMisconfigScan(JTextArea output) {
        log("INFO", "Running Misconfig scan...");
        output.setText("");

        new Thread(() -> {
            try {
                ProcessBuilder pb = new ProcessBuilder(
                        "C:\\ShieldX\\services\\misconfig\\bin\\shieldx_c.exe"
                );
                pb.redirectErrorStream(true);
                Process p = pb.start();

                BufferedReader reader = new BufferedReader(
                        new InputStreamReader(p.getInputStream())
                );

                String line;
                while ((line = reader.readLine()) != null) {
                    String l = line;
                    SwingUtilities.invokeLater(() -> output.append(l + "\n"));
                }

                p.waitFor();
                log("SUCCESS", "Misconfig scan completed");

            } catch (Exception ex) {
                log("ERROR", ex.getMessage());
            }
        }).start();
    }

    static void runPhishingScan(String url, JTextArea output) {
        if (url.isBlank() || url.equals("Paste the link here")) {
            log("ERROR", "No URL provided");
            return;
        }

        log("INFO", "Running phishing scan...");
        output.setText("");

        new Thread(() -> {
            try {
                ProcessBuilder pb = new ProcessBuilder("python", "checker.py", url);
                pb.directory(new File("C:\\ShieldX\\services\\phishing"));
                pb.redirectErrorStream(true);

                Process p = pb.start();
                BufferedReader reader = new BufferedReader(
                        new InputStreamReader(p.getInputStream())
                );

                String line;
                while ((line = reader.readLine()) != null) {
                    String l = line;
                    SwingUtilities.invokeLater(() -> output.append(l + "\n"));
                }

                p.waitFor();
                log("SUCCESS", "Phishing scan completed");

            } catch (Exception ex) {
                log("ERROR", ex.getMessage());
            }
        }).start();
    }

    static JPanel logPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBackground(BG_PANEL);

        logPane = new JTextPane();
        logPane.setEditable(false);
        logPane.setBackground(new Color(10, 14, 18));
        logPane.setFont(new Font("JetBrains Mono", Font.PLAIN, 13));
        attachContextMenu(logPane);

        JScrollPane scroll = new JScrollPane(logPane);

        JButton clear = new JButton("Clear Logs");
        clear.addActionListener(e -> logPane.setText(""));

        JPanel top = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        top.setBackground(BG_PANEL);
        top.add(clear);

        panel.add(top, BorderLayout.NORTH);
        panel.add(scroll, BorderLayout.CENTER);
        return panel;
    }

    static void attachContextMenu(JTextComponent c) {
        JPopupMenu menu = new JPopupMenu();

        JMenuItem paste = new JMenuItem("Paste");
        paste.addActionListener(e -> c.paste());

        JMenuItem copy = new JMenuItem("Copy");
        copy.addActionListener(e -> c.copy());

        JMenuItem selectAll = new JMenuItem("Select All");
        selectAll.addActionListener(e -> c.selectAll());

        JMenuItem open = new JMenuItem("Open URL");
        open.addActionListener(e -> {
            try {
                String t = c.getSelectedText();
                if (t != null && t.startsWith("http"))
                    Desktop.getDesktop().browse(new URI(t.trim()));
            } catch (Exception ignored) {}
        });

        menu.add(paste);
        menu.add(copy);
        menu.add(selectAll);
        menu.addSeparator();
        menu.add(open);

        c.setComponentPopupMenu(menu);
    }

    static void log(String type, String msg) {
        StyledDocument doc = logPane.getStyledDocument();
        Style style = logPane.addStyle(type, null);
        Color c = switch (type) {
            case "ERROR" -> ERROR;
            case "SUCCESS" -> SUCCESS;
            default -> INFO;
        };
        StyleConstants.setForeground(style, c);

        String time = LocalTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss"));
        try {
            doc.insertString(doc.getLength(),
                    "[" + time + "] [" + type + "] " + msg + "\n",
                    style);
        } catch (Exception ignored) {}
    }
}
