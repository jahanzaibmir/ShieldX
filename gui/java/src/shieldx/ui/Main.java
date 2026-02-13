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
import java.util.ArrayList;
import java.util.List;

public class Main {

    static final Color BG_MAIN = new Color(0x0D1117);
    static final Color BG_PANEL = new Color(0x161B22);
    static final Color ACCENT = new Color(0x00E5FF);
    static final Color SUCCESS = new Color(0x2ECC71);
    static final Color ERROR = new Color(0xFF6B6B);
    static final Color INFO = new Color(0x4DA3FF);
    static final Color WARNING = new Color(0xFFB74D);
    static final Color PLACEHOLDER = new Color(120, 120, 120);

    static JTextPane logPane;
    static JPanel topPanel;
    
    // *** DYNAMIC PATH DETECTION - WORKS ON ANY DRIVE! ***
    private static final String PROJECT_ROOT = findProjectRoot();
    private static final String COLLECTOR_EXE = PROJECT_ROOT + "\\services\\misconfig\\collectors\\c\\shieldx-collector.exe";
    private static final String ENGINE_EXE = PROJECT_ROOT + "\\services\\misconfig\\engine\\target\\release\\shieldx-engine.exe";
    private static final String STATE_JSON = PROJECT_ROOT + "\\services\\misconfig\\engine\\state.json";
    private static final String PHISHING_DIR = PROJECT_ROOT + "\\services\\phishing";
    private static final String MALWARE_DIR = PROJECT_ROOT + "\\services\\malware";
    private static final String TEMP_INTERFACES = PROJECT_ROOT + "\\temp_interfaces.json";
    
    /**
     * Automatically find ShieldX project root directory
     * Works on ANY drive (C:, D:, E:, etc.)
     */
    private static String findProjectRoot() {
        try {
            // Method 1: Get location of running .class file
            String classPath = Main.class.getProtectionDomain().getCodeSource().getLocation().getPath();
            File classFile = new File(classPath);
            
            // Decode URL encoding (spaces become %20, etc.)
            classPath = java.net.URLDecoder.decode(classPath, "UTF-8");
            
            // Remove leading "/" from Windows paths (e.g., "/C:/..." -> "C:/...")
            if (classPath.startsWith("/") && classPath.contains(":")) {
                classPath = classPath.substring(1);
            }
            
            File current = new File(classPath);
            
            // Navigate up from wherever we are to find ShieldX root
            // Look for marker files/folders that indicate project root
            while (current != null && current.getParentFile() != null) {
                File parent = current.getParentFile();
                
                // Check if this is ShieldX root (contains "services" directory)
                File servicesDir = new File(parent, "services");
                File misconfigDir = new File(servicesDir, "misconfig");
                
                if (servicesDir.exists() && misconfigDir.exists()) {
                    String rootPath = parent.getAbsolutePath();
                    System.out.println("[ShieldX] Project root detected: " + rootPath);
                    return rootPath;
                }
                
                current = parent;
            }
            
            // Method 2: Check current working directory
            String userDir = System.getProperty("user.dir");
            File workDir = new File(userDir);
            
            // Check if CWD is ShieldX root
            if (new File(workDir, "services\\misconfig").exists()) {
                System.out.println("[ShieldX] Using working directory: " + userDir);
                return userDir;
            }
            
            // Check if CWD is inside ShieldX (go up to find root)
            current = workDir;
            while (current != null && current.getParentFile() != null) {
                File servicesDir = new File(current, "services");
                if (servicesDir.exists() && new File(servicesDir, "misconfig").exists()) {
                    System.out.println("[ShieldX] Found root from CWD: " + current.getAbsolutePath());
                    return current.getAbsolutePath();
                }
                current = current.getParentFile();
            }
            
            // Method 3: Fallback - ask user
            System.err.println("[ShieldX] Could not auto-detect project root!");
            System.err.println("[ShieldX] Please run from ShieldX directory or set SHIELDX_HOME");
            
            // Try environment variable as last resort
            String envRoot = System.getenv("SHIELDX_HOME");
            if (envRoot != null && new File(envRoot, "services\\misconfig").exists()) {
                System.out.println("[ShieldX] Using SHIELDX_HOME: " + envRoot);
                return envRoot;
            }
            
            // Ultimate fallback - show dialog
            JFileChooser chooser = new JFileChooser();
            chooser.setDialogTitle("Select ShieldX Root Directory");
            chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
            
            if (chooser.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) {
                String selected = chooser.getSelectedFile().getAbsolutePath();
                System.out.println("[ShieldX] User selected: " + selected);
                return selected;
            }
            
            throw new RuntimeException("Could not determine ShieldX project root directory!");
            
        } catch (Exception e) {
            e.printStackTrace();
            // Last ditch effort - assume C:\ShieldX
            System.err.println("[ShieldX] ERROR: Falling back to C:\\ShieldX");
            return "C:\\ShieldX";
        }
    }
    
    /**
     * Verify all required paths exist on startup
     */
    private static void verifyPaths() {
        System.out.println("\n=== ShieldX Path Configuration ===");
        System.out.println("Project Root: " + PROJECT_ROOT);
        System.out.println("C Collector:  " + COLLECTOR_EXE);
        System.out.println("Rust Engine:  " + ENGINE_EXE);
        System.out.println("Phishing Dir: " + PHISHING_DIR);
        System.out.println("Malware Dir:  " + MALWARE_DIR);
        System.out.println("==================================\n");
        
        // Check if critical files exist
        if (!new File(COLLECTOR_EXE).exists()) {
            System.err.println("[WARNING] Collector not found: " + COLLECTOR_EXE);
            System.err.println("          Please compile the C collector first!");
        }
        
        if (!new File(ENGINE_EXE).exists()) {
            System.err.println("[WARNING] Engine not found: " + ENGINE_EXE);
            System.err.println("          Please compile the Rust engine first!");
        }
        
        if (!new File(PHISHING_DIR).exists()) {
            System.err.println("[WARNING] Phishing module not found: " + PHISHING_DIR);
        }
        
        if (!new File(MALWARE_DIR).exists()) {
            System.err.println("[INFO] Malware module directory will be created on first use");
        }
    }

    public static void main(String[] args) {
        // Verify paths on startup
        verifyPaths();
        
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
        JMenuItem malware = new JMenuItem("Malware Analysis");
        malware.addActionListener(e -> malwareUI());
        tools.add(phishing);
        tools.add(misconfig);
        tools.add(malware);

        JMenu help = new JMenu("Help");
        JMenuItem about = new JMenuItem("About ShieldX");
        about.addActionListener(e ->
                JOptionPane.showMessageDialog(
                        frame,
                        "ShieldX\nAn Enterprise SOC Platform\nVersion 1.0\n2026\nDeveloped By Jahanzaib Ashraf Mir\n All praise is for Allah",
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
        sidebar.add(sidebarButton("Malware", Main::malwareUI));

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
        log("INFO", "Project root: " + PROJECT_ROOT);
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

    // ---------------- PHISHING PANEL ----------------
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

    // ---------------- MALWARE ANALYSIS PANEL ----------------
    static void malwareUI() {
        topPanel.removeAll();
        topPanel.setLayout(new BorderLayout(20, 20));
        topPanel.setBorder(BorderFactory.createEmptyBorder(40, 40, 40, 40));

        JLabel title = new JLabel("Malware Analysis");
        title.setForeground(Color.WHITE);
        title.setFont(new Font("Inter", Font.BOLD, 26));

        // File selection panel
        JPanel filePanel = new JPanel(new BorderLayout(10, 10));
        filePanel.setBackground(BG_MAIN);

        JTextField filePathField = new JTextField("No file selected");
        filePathField.setEditable(false);
        filePathField.setForeground(PLACEHOLDER);
        filePathField.setBackground(BG_PANEL);
        filePathField.setFont(new Font("Inter", Font.PLAIN, 14));
        filePathField.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));

        JButton browseBtn = new JButton("Browse File");
        browseBtn.setBackground(INFO);
        browseBtn.setForeground(Color.WHITE);
        browseBtn.addActionListener(e -> {
            JFileChooser chooser = new JFileChooser();
            chooser.setDialogTitle("Select File to Analyze");
            if (chooser.showOpenDialog(topPanel) == JFileChooser.APPROVE_OPTION) {
                filePathField.setText(chooser.getSelectedFile().getAbsolutePath());
                filePathField.setForeground(Color.WHITE);
            }
        });

        JButton scanBtn = new JButton("Analyze File");
        scanBtn.setBackground(ACCENT);
        scanBtn.setForeground(Color.WHITE);

        filePanel.add(filePathField, BorderLayout.CENTER);
        filePanel.add(browseBtn, BorderLayout.EAST);

        JTextArea output = new JTextArea();
        output.setEditable(false);
        output.setFont(new Font("JetBrains Mono", Font.PLAIN, 13));
        output.setBackground(new Color(10, 14, 18));
        output.setForeground(Color.WHITE);
        attachContextMenu(output);

        scanBtn.addActionListener(e -> {
            String filePath = filePathField.getText();
            if (filePath.equals("No file selected")) {
                log("ERROR", "No file selected for analysis");
                JOptionPane.showMessageDialog(topPanel,
                    "Please select a file to analyze!",
                    "No File Selected",
                    JOptionPane.WARNING_MESSAGE);
                return;
            }
            runMalwareAnalysis(filePath, output);
        });

        JPanel top = new JPanel(new BorderLayout(10, 10));
        top.setBackground(BG_MAIN);
        top.add(title, BorderLayout.NORTH);
        top.add(filePanel, BorderLayout.CENTER);
        top.add(scanBtn, BorderLayout.EAST);

        topPanel.add(top, BorderLayout.NORTH);
        topPanel.add(new JScrollPane(output), BorderLayout.CENTER);
        topPanel.revalidate();
        topPanel.repaint();
    }

    static void runMalwareAnalysis(String filePath, JTextArea output) {
        log("INFO", "Running malware analysis on: " + filePath);
        output.setText("Analyzing file: " + filePath + "\n\n");

        new Thread(() -> {
            try {
                File targetFile = new File(filePath);
                
                SwingUtilities.invokeLater(() -> {
                    output.append("=========================================\n");
                    output.append("     MALWARE ANALYSIS REPORT\n");
                    output.append("=========================================\n\n");
                    output.append("File: " + targetFile.getName() + "\n");
                    output.append("Size: " + targetFile.length() + " bytes\n");
                    output.append("Path: " + filePath + "\n\n");
                    output.append("=========================================\n");
                    output.append("     ANALYSIS IN PROGRESS\n");
                    output.append("=========================================\n\n");
                    output.append("[*] Computing file hash...\n");
                    output.append("[*] Checking file signature...\n");
                    output.append("[*] Analyzing entropy...\n");
                    output.append("[*] Scanning for suspicious strings...\n");
                    output.append("[*] Checking against threat database...\n\n");
                    output.append("=========================================\n");
                    output.append("     RESULTS\n");
                    output.append("=========================================\n\n");
                    output.append("[INFO] This is a placeholder for the malware analysis module.\n");
                    output.append("[INFO] Full implementation coming in next update!\n\n");
                    output.append("Features to be added:\n");
                    output.append("  - Static analysis (strings, entropy, PE headers)\n");
                    output.append("  - Dynamic analysis (behavior monitoring)\n");
                    output.append("  - YARA rule scanning\n");
                    output.append("  - VirusTotal integration\n");
                    output.append("  - Sandbox execution\n");
                    output.append("  - IOC extraction\n\n");
                });

                log("SUCCESS", "Malware analysis placeholder completed");

            } catch (Exception ex) {
                log("ERROR", ex.getMessage());
                SwingUtilities.invokeLater(() ->
                    output.append("\nERROR: " + ex.getMessage() + "\n")
                );
            }
        }).start();
    }

   // ---------------- ENHANCED MISCONFIG PANEL WITH TABS ----------------
    static void misconfigUI() {
        topPanel.removeAll();
        topPanel.setLayout(new BorderLayout(20, 20));
        topPanel.setBorder(BorderFactory.createEmptyBorder(40, 40, 40, 40));

        JLabel title = new JLabel("Misconfiguration Detection");
        title.setForeground(Color.WHITE);
        title.setFont(new Font("Inter", Font.BOLD, 26));

        // Interface selection panel
        JPanel controlPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 10));
        controlPanel.setBackground(BG_MAIN);
        
        JLabel interfaceLabel = new JLabel("Select Interface:");
        interfaceLabel.setForeground(Color.WHITE);
        interfaceLabel.setFont(new Font("Inter", Font.PLAIN, 14));
        
        JComboBox<String> interfaceCombo = new JComboBox<>();
        interfaceCombo.setBackground(BG_PANEL);
        interfaceCombo.setForeground(Color.WHITE);
        interfaceCombo.setFont(new Font("Inter", Font.PLAIN, 14));
        interfaceCombo.setPreferredSize(new Dimension(250, 30));
        
        JButton refreshBtn = new JButton("[Refresh]");
        refreshBtn.setBackground(INFO);
        refreshBtn.setForeground(Color.WHITE);
        refreshBtn.addActionListener(e -> loadNetworkInterfaces(interfaceCombo));
        
        JButton scanBtn = new JButton("[Run Full Scan]");
        scanBtn.setBackground(ACCENT);
        scanBtn.setForeground(Color.WHITE);
        scanBtn.setFont(new Font("Inter", Font.BOLD, 14));
        
        controlPanel.add(interfaceLabel);
        controlPanel.add(interfaceCombo);
        controlPanel.add(refreshBtn);
        controlPanel.add(Box.createHorizontalStrut(20));
        controlPanel.add(scanBtn);

        // Create tabbed pane for organized results
        JTabbedPane tabbedPane = new JTabbedPane();
        tabbedPane.setBackground(BG_MAIN);
        tabbedPane.setForeground(Color.WHITE);
        tabbedPane.setFont(new Font("Inter", Font.BOLD, 13));

        // Tab 1: Overview / Summary
        JTextArea overviewArea = createStyledTextArea();
        tabbedPane.addTab("[Overview]", new JScrollPane(overviewArea));

        // Tab 2: Network Interfaces
        JTextArea interfacesArea = createStyledTextArea();
        tabbedPane.addTab("[Interfaces]", new JScrollPane(interfacesArea));

        // Tab 3: Open Ports
        JTextArea portsArea = createStyledTextArea();
        tabbedPane.addTab("[Open Ports]", new JScrollPane(portsArea));

        // Tab 4: Active Services
        JTextArea servicesArea = createStyledTextArea();
        tabbedPane.addTab("[Services]", new JScrollPane(servicesArea));

        // Tab 5: WiFi Security
        JTextArea wifiArea = createStyledTextArea();
        tabbedPane.addTab("[WiFi]", new JScrollPane(wifiArea));

        // Tab 6: Connections
        JTextArea connectionsArea = createStyledTextArea();
        tabbedPane.addTab("[Connections]", new JScrollPane(connectionsArea));

        // Tab 7: Security Findings
        JTextArea findingsArea = createStyledTextArea();
        tabbedPane.addTab("[Findings]", new JScrollPane(findingsArea));

        // Tab 8: Raw Output
        JTextArea rawOutputArea = createStyledTextArea();
        tabbedPane.addTab("[Raw Output]", new JScrollPane(rawOutputArea));

        // Scan button action
        scanBtn.addActionListener(e -> {
            String selectedInterface = (String) interfaceCombo.getSelectedItem();
            if (selectedInterface == null || selectedInterface.isEmpty()) {
                log("ERROR", "No interface selected");
                JOptionPane.showMessageDialog(topPanel, 
                    "Please select a network interface first!", 
                    "No Interface Selected", 
                    JOptionPane.WARNING_MESSAGE);
                return;
            }
            
            // Clear all tabs
            overviewArea.setText("Scanning...\n");
            interfacesArea.setText("");
            portsArea.setText("");
            servicesArea.setText("");
            wifiArea.setText("");
            connectionsArea.setText("");
            findingsArea.setText("");
            rawOutputArea.setText("");
            
            // Run scan with organized output
            runOrganizedMisconfigScan(selectedInterface, overviewArea, interfacesArea, 
                                    portsArea, servicesArea, wifiArea, connectionsArea, 
                                    findingsArea, rawOutputArea);
        });

        JPanel topSection = new JPanel(new BorderLayout(10, 10));
        topSection.setBackground(BG_MAIN);
        topSection.add(title, BorderLayout.NORTH);
        topSection.add(controlPanel, BorderLayout.CENTER);

        topPanel.add(topSection, BorderLayout.NORTH);
        topPanel.add(tabbedPane, BorderLayout.CENTER);
        topPanel.revalidate();
        topPanel.repaint();
        
        // Auto-load interfaces
        loadNetworkInterfaces(interfaceCombo);
    }

    static JTextArea createStyledTextArea() {
        JTextArea area = new JTextArea();
        area.setEditable(false);
        area.setFont(new Font("JetBrains Mono", Font.PLAIN, 13));
        area.setBackground(new Color(10, 14, 18));
        area.setForeground(Color.WHITE);
        area.setLineWrap(false);
        area.setWrapStyleWord(false);
        attachContextMenu(area);
        return area;
    }

    static void runOrganizedMisconfigScan(String selectedInterface, 
                                         JTextArea overview, JTextArea interfaces, 
                                         JTextArea ports, JTextArea services, 
                                         JTextArea wifi, JTextArea connections,
                                         JTextArea findings, JTextArea rawOutput) {
        log("INFO", "Running organized scan on: " + selectedInterface);

        new Thread(() -> {
            try {
                // *** FIXED: Use dynamic paths ***
                ProcessBuilder collectorPb = new ProcessBuilder(
                    COLLECTOR_EXE,
                    "-m", "network",
                    "-o", STATE_JSON,
                    "-v"
                );
                collectorPb.redirectErrorStream(true);
                Process collectorP = collectorPb.start();
                
                BufferedReader collectorReader = new BufferedReader(
                    new InputStreamReader(collectorP.getInputStream())
                );
                
                String line;
                StringBuilder rawData = new StringBuilder();
                while ((line = collectorReader.readLine()) != null) {
                    String l = line;
                    rawData.append(l).append("\n");
                    SwingUtilities.invokeLater(() -> rawOutput.append(l + "\n"));
                }
                
                collectorP.waitFor();
                
                // Parse the JSON output
                String jsonContent = new String(java.nio.file.Files.readAllBytes(
                    java.nio.file.Paths.get(STATE_JSON)));
                
                // Parse and display organized data
                SwingUtilities.invokeLater(() -> {
                    parseAndDisplayData(jsonContent, overview, interfaces, ports, 
                                      services, wifi, connections, findings);
                });
                
                // Run Rust engine
                SwingUtilities.invokeLater(() -> rawOutput.append("\n--- Running Analysis Engine ---\n\n"));
                
                ProcessBuilder enginePb = new ProcessBuilder(
                    ENGINE_EXE,
                    STATE_JSON
                );
                enginePb.redirectErrorStream(true);
                Process engineP = enginePb.start();

                BufferedReader engineReader = new BufferedReader(
                    new InputStreamReader(engineP.getInputStream())
                );

                while ((line = engineReader.readLine()) != null) {
                    String l = line;
                    SwingUtilities.invokeLater(() -> rawOutput.append(l + "\n"));
                }

                engineP.waitFor();
                log("SUCCESS", "Scan completed for " + selectedInterface);

            } catch (Exception ex) {
                log("ERROR", ex.getMessage());
                SwingUtilities.invokeLater(() -> 
                    rawOutput.append("\nERROR: " + ex.getMessage() + "\n")
                );
            }
        }).start();
    }

    static void parseAndDisplayData(String json, JTextArea overview, JTextArea interfaces,
                                   JTextArea ports, JTextArea services, JTextArea wifi,
                                   JTextArea connections, JTextArea findings) {
        try {
            // Parse Overview
            int ifaceCount = countMatches(json, "\"is_up\": true");
            int portCount = countMatches(json, "\"type\": \"risky_port\"");
            int suspiciousConns = countMatches(json, "\"type\": \"suspicious_connection\"");
            boolean firewallEnabled = json.contains("\"firewall_enabled\": true");
            
            StringBuilder overviewText = new StringBuilder();
            overviewText.append("=========================================\n");
            overviewText.append("     NETWORK SECURITY OVERVIEW\n");
            overviewText.append("=========================================\n\n");
            overviewText.append(String.format("Active Interfaces:      %d\n", ifaceCount));
            overviewText.append(String.format("Open Ports:             %d\n", portCount));
            overviewText.append(String.format("Suspicious Connections: %d\n", suspiciousConns));
            overviewText.append(String.format("Firewall Status:        %s\n\n", 
                firewallEnabled ? "[OK] ENABLED" : "[X] DISABLED"));
            
            if (!firewallEnabled) {
                overviewText.append("[!] WARNING: Windows Firewall is DISABLED!\n");
                overviewText.append("    This is a CRITICAL security risk.\n\n");
            }
            
            if (portCount > 0) {
                overviewText.append(String.format("[!] %d risky ports detected\n", portCount));
            }
            
            if (suspiciousConns > 5) {
                overviewText.append(String.format("[!] %d suspicious connections found\n", suspiciousConns));
            }
            
            overview.setText(overviewText.toString());
            
            // Parse Network Interfaces
            parseInterfaces(json, interfaces);
            
            // Parse Open Ports
            parsePorts(json, ports);
            
            // Parse Services
            parseServices(json, services);
            
            // Parse WiFi
            parseWiFi(json, wifi);
            
            // Parse Connections
            parseConnections(json, connections);
            
            // Parse Findings
            parseFindings(json, findings);
            
        } catch (Exception e) {
            overview.setText("Error parsing data: " + e.getMessage());
        }
    }

    static int countMatches(String text, String pattern) {
        int count = 0;
        int index = 0;
        while ((index = text.indexOf(pattern, index)) != -1) {
            count++;
            index += pattern.length();
        }
        return count;
    }

    static void parseInterfaces(String json, JTextArea output) {
        StringBuilder text = new StringBuilder();
        text.append("=========================================\n");
        text.append("     NETWORK INTERFACES\n");
        text.append("=========================================\n\n");
        
        int start = json.indexOf("\"interfaces\": [");
        if (start == -1) {
            output.setText("No interface data found");
            return;
        }
        
        int ifaceNum = 1;
        int pos = start;
        while (true) {
            int nameStart = json.indexOf("\"name\": \"", pos);
            if (nameStart == -1 || nameStart > json.indexOf("]", start)) break;
            nameStart += 9;
            int nameEnd = json.indexOf("\"", nameStart);
            String name = json.substring(nameStart, nameEnd);
            
            String ipv4 = extractValue(json, "\"ipv4\": \"", nameStart);
            String mac = extractValue(json, "\"mac\": \"", nameStart);
            String isUp = extractValue(json, "\"is_up\": ", nameStart);
            String isWireless = extractValue(json, "\"is_wireless\": ", nameStart);
            
            text.append(String.format("Interface #%d\n", ifaceNum++));
            text.append(String.format("  Name:       %s\n", name));
            text.append(String.format("  IP Address: %s\n", ipv4.isEmpty() ? "N/A" : ipv4));
            text.append(String.format("  MAC:        %s\n", mac.isEmpty() ? "N/A" : mac));
            text.append(String.format("  Status:     %s\n", isUp.equals("true") ? "[OK] UP" : "[X] DOWN"));
            text.append(String.format("  Type:       %s\n", isWireless.equals("true") ? "Wireless" : "Wired"));
            text.append("\n");
            
            pos = nameEnd;
        }
        
        output.setText(text.toString());
    }

    static void parsePorts(String json, JTextArea output) {
        StringBuilder text = new StringBuilder();
        text.append("=========================================\n");
        text.append("     OPEN PORTS & SERVICES\n");
        text.append("=========================================\n\n");
        
        int count = 1;
        int pos = 0;
        while (true) {
            int findingStart = json.indexOf("\"type\": \"risky_port\"", pos);
            if (findingStart == -1) break;
            
            String port = extractValue(json, "\"port\": ", findingStart);
            String service = extractValue(json, "\"service\": \"", findingStart);
            String binding = extractValue(json, "\"binding\": \"", findingStart);
            String riskLevel = extractValue(json, "\"risk_level\": \"", findingStart);
            
            text.append(String.format("[%d] Port %s - %s\n", count++, port, service));
            text.append(String.format("    Binding:    %s\n", binding));
            text.append(String.format("    Risk Level: %s %s\n", getRiskTag(riskLevel), riskLevel.toUpperCase()));
            text.append("\n");
            
            pos = findingStart + 20;
        }
        
        if (count == 1) {
            text.append("[OK] No risky ports detected\n");
        }
        
        output.setText(text.toString());
    }

    static void parseServices(String json, JTextArea output) {
        output.setText("Services analysis will be displayed here...\n(Implementation in progress)");
    }

    static void parseWiFi(String json, JTextArea output) {
        StringBuilder text = new StringBuilder();
        text.append("=========================================\n");
        text.append("     WiFi SECURITY ANALYSIS\n");
        text.append("=========================================\n\n");
        
        int pos = 0;
        boolean foundWifi = false;
        while (true) {
            int wifiStart = json.indexOf("\"is_wireless\": true", pos);
            if (wifiStart == -1) break;
            
            foundWifi = true;
            String name = extractValue(json, "\"name\": \"", wifiStart - 200);
            String ipv4 = extractValue(json, "\"ipv4\": \"", wifiStart);
            
            text.append(String.format("WiFi Interface: %s\n", name));
            text.append(String.format("  IP Address: %s\n", ipv4));
            text.append("  Encryption: (Available in next update)\n");
            text.append("  Signal:     (Available in next update)\n");
            text.append("  SSID:       (Available in next update)\n\n");
            
            pos = wifiStart + 20;
        }
        
        if (!foundWifi) {
            text.append("[i] No active WiFi interfaces detected\n");
        }
        
        output.setText(text.toString());
    }

    static void parseConnections(String json, JTextArea output) {
        StringBuilder text = new StringBuilder();
        text.append("=========================================\n");
        text.append("     ACTIVE CONNECTIONS\n");
        text.append("=========================================\n\n");
        
        int suspicious = countMatches(json, "\"type\": \"suspicious_connection\"");
        text.append(String.format("Suspicious Connections: %d\n\n", suspicious));
        
        if (suspicious > 0) {
            text.append("[!] Potentially malicious activity detected!\n");
            text.append("    Review connections in Security Findings tab\n");
        } else {
            text.append("[OK] No suspicious connections detected\n");
        }
        
        output.setText(text.toString());
    }

    static void parseFindings(String json, JTextArea output) {
        StringBuilder text = new StringBuilder();
        text.append("=========================================\n");
        text.append("     SECURITY FINDINGS\n");
        text.append("=========================================\n\n");
        
        boolean firewallEnabled = json.contains("\"firewall_enabled\": true");
        if (!firewallEnabled) {
            text.append("[CRITICAL] Firewall Disabled\n");
            text.append("  >> Enable Windows Firewall immediately\n\n");
        }
        
        int riskyPorts = countMatches(json, "\"type\": \"risky_port\"");
        if (riskyPorts > 0) {
            text.append(String.format("[HIGH] %d Risky Ports Exposed\n", riskyPorts));
            text.append("  >> See 'Open Ports' tab for details\n\n");
        }
        
        int suspicious = countMatches(json, "\"type\": \"suspicious_connection\"");
        if (suspicious > 10) {
            text.append(String.format("[MEDIUM] %d Suspicious Connections\n", suspicious));
            text.append("  >> Monitor network traffic for malware\n\n");
        }
        
        output.setText(text.toString());
    }

    static String extractValue(String json, String key, int startPos) {
        int start = json.indexOf(key, startPos);
        if (start == -1 || start > startPos + 1000) return "";
        start += key.length();
        int end = json.indexOf(key.contains("\"") ? "\"" : ",", start);
        if (end == -1) end = json.indexOf("}", start);
        return json.substring(start, end).trim();
    }

    static String getRiskTag(String risk) {
        return switch (risk.toLowerCase()) {
            case "critical" -> "[CRIT]";
            case "high" -> "[HIGH]";
            case "medium" -> "[MED]";
            case "low" -> "[LOW]";
            default -> "[i]";
        };
    }
    
    // ---------------- LOAD NETWORK INTERFACES ----------------
    static void loadNetworkInterfaces(JComboBox<String> combo) {
        log("INFO", "Loading network interfaces...");
        combo.removeAllItems();
        
        new Thread(() -> {
            try {
                // *** FIXED: Use dynamic paths ***
                ProcessBuilder pb = new ProcessBuilder(
                    COLLECTOR_EXE,
                    "-m", "network",
                    "-o", TEMP_INTERFACES
                );
                pb.redirectErrorStream(true);
                Process p = pb.start();
                p.waitFor();
                
                // Read the JSON output
                java.nio.file.Path path = java.nio.file.Paths.get(TEMP_INTERFACES);
                String content = new String(java.nio.file.Files.readAllBytes(path));
                
                // Parse JSON to extract interfaces (simple parsing)
                List<String> interfaces = parseInterfaces(content);
                
                SwingUtilities.invokeLater(() -> {
                    for (String iface : interfaces) {
                        combo.addItem(iface);
                    }
                    if (combo.getItemCount() > 0) {
                        combo.setSelectedIndex(0);
                        log("SUCCESS", "Loaded " + interfaces.size() + " network interfaces");
                    } else {
                        log("WARNING", "No interfaces found");
                    }
                });
                
            } catch (Exception ex) {
                log("ERROR", "Failed to load interfaces: " + ex.getMessage());
            }
        }).start();
    }
    
    // Simple JSON parser for interfaces
    static List<String> parseInterfaces(String json) {
        List<String> interfaces = new ArrayList<>();
        
        try {
            // Find the "interfaces" array in JSON
            int interfacesStart = json.indexOf("\"interfaces\": [");
            if (interfacesStart == -1) {
                interfaces.add("All Interfaces (Default)");
                return interfaces;
            }
            
            // Extract interface objects
            int currentPos = interfacesStart;
            while (true) {
                int nameStart = json.indexOf("\"name\": \"", currentPos);
                if (nameStart == -1) break;
                nameStart += 9; // Length of "\"name\": \""
                int nameEnd = json.indexOf("\"", nameStart);
                String name = json.substring(nameStart, nameEnd);
                
                // Find IPv4 address
                int ipv4Start = json.indexOf("\"ipv4\": \"", nameStart);
                String ipv4 = "";
                if (ipv4Start != -1 && ipv4Start < json.indexOf("}", nameStart)) {
                    ipv4Start += 9;
                    int ipv4End = json.indexOf("\"", ipv4Start);
                    ipv4 = json.substring(ipv4Start, ipv4End);
                }
                
                // Find is_up status
                int isUpPos = json.indexOf("\"is_up\": ", nameStart);
                boolean isUp = false;
                if (isUpPos != -1 && isUpPos < json.indexOf("}", nameStart)) {
                    isUp = json.substring(isUpPos + 9, isUpPos + 13).equals("true");
                }
                
                // Only add interfaces that are UP and have an IP
                if (isUp && ipv4 != null && !ipv4.isEmpty()) {
                    String displayName = name + " - " + ipv4;
                    interfaces.add(displayName);
                }
                
                currentPos = nameEnd + 1;
                
                // Check if we've reached the end of interfaces array
                int nextBracket = json.indexOf("]", currentPos);
                int nextComma = json.indexOf(",", currentPos);
                if (nextComma == -1 || nextBracket < nextComma) {
                    break;
                }
            }
            
        } catch (Exception e) {
            System.err.println("Error parsing interfaces: " + e.getMessage());
        }
        
        if (interfaces.isEmpty()) {
            interfaces.add("All Interfaces (Default)");
        }
        
        return interfaces;
    }

    // ---------------- RUN SCANS ----------------
    static void runMisconfigScan(String selectedInterface, JTextArea output) {
        log("INFO", "Running Misconfig scan on: " + selectedInterface);
        output.setText("Scanning interface: " + selectedInterface + "\n\n");

        new Thread(() -> {
            try {
                // *** FIXED: Use dynamic paths ***
                ProcessBuilder collectorPb = new ProcessBuilder(
                    COLLECTOR_EXE,
                    "-m", "network",
                    "-o", STATE_JSON,
                    "-v"
                );
                collectorPb.redirectErrorStream(true);
                Process collectorP = collectorPb.start();
                
                BufferedReader collectorReader = new BufferedReader(
                    new InputStreamReader(collectorP.getInputStream())
                );
                
                String line;
                while ((line = collectorReader.readLine()) != null) {
                    String l = line;
                    SwingUtilities.invokeLater(() -> output.append("[C Collector] " + l + "\n"));
                }
                
                collectorP.waitFor();
                
                SwingUtilities.invokeLater(() -> output.append("\n--- Running Rust Analysis Engine ---\n\n"));
                
                // Then run Rust engine on the collected data
                ProcessBuilder enginePb = new ProcessBuilder(
                    ENGINE_EXE,
                    STATE_JSON
                );
                enginePb.redirectErrorStream(true);
                Process engineP = enginePb.start();

                BufferedReader engineReader = new BufferedReader(
                    new InputStreamReader(engineP.getInputStream())
                );

                while ((line = engineReader.readLine()) != null) {
                    String l = line;
                    SwingUtilities.invokeLater(() -> output.append(l + "\n"));
                }

                engineP.waitFor();
                log("SUCCESS", "Misconfig scan completed for " + selectedInterface);

            } catch (Exception ex) {
                log("ERROR", ex.getMessage());
                SwingUtilities.invokeLater(() -> 
                    output.append("\nERROR: " + ex.getMessage() + "\n")
                );
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
                // *** FIXED: Use dynamic path ***
                ProcessBuilder pb = new ProcessBuilder("python", "checker.py", url);
                pb.directory(new File(PHISHING_DIR));
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

    // ---------------- LOG PANEL ----------------
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

    // ---------------- UTILITIES ----------------
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
            case "WARNING" -> WARNING;
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
