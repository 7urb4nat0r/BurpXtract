package burp;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.event.*;
import java.util.List;
import java.util.ArrayList;
import java.io.File;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.DocumentBuilder;
import org.w3c.dom.*;

public class BurpHistoryPanel extends JPanel {
    private final BurpHistoryTableModel tableModel;
    private final JTable table;
    private final TableRowSorter<BurpHistoryTableModel> sorter;
    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private final JTextField filterField;
    private final JButton clearButton;
    private final JButton importButton;
    private final RequestResponseViewer viewer;

    private List<BurpEntry> allEntries = new ArrayList<>();

    // Debounce timer for filter updates
    private Timer filterTimer;

    public BurpHistoryPanel(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers) {
        super(new BorderLayout());
        this.callbacks = callbacks;
        this.helpers = helpers;

        // Table model and sorter
        tableModel = new BurpHistoryTableModel();
        sorter = new TableRowSorter<>(tableModel);
        table = new JTable(tableModel);
        table.setRowSorter(sorter);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setFillsViewportHeight(true);
        table.getTableHeader().setReorderingAllowed(false);

        // "No." column numeric sort
        sorter.setComparator(0, (o1, o2) -> {
            Integer n1 = (o1 instanceof Integer) ? (Integer)o1 : Integer.parseInt(o1.toString());
            Integer n2 = (o2 instanceof Integer) ? (Integer)o2 : Integer.parseInt(o2.toString());
            return n1.compareTo(n2);
        });

        // Column widths for your requested order
        table.getColumnModel().getColumn(0).setPreferredWidth(40);   // No.
        table.getColumnModel().getColumn(1).setPreferredWidth(120);  // Host
        table.getColumnModel().getColumn(2).setPreferredWidth(60);   // Method
        table.getColumnModel().getColumn(3).setPreferredWidth(250);  // URL
        table.getColumnModel().getColumn(4).setPreferredWidth(60);   // Status
        table.getColumnModel().getColumn(5).setPreferredWidth(80);   // Length
        table.getColumnModel().getColumn(6).setPreferredWidth(90);   // MIME Type
        table.getColumnModel().getColumn(7).setPreferredWidth(120);  // IP

        // Filter bar
        JPanel filterPanel = new JPanel(new BorderLayout(5, 0));
        filterField = new JTextField();
        filterField.setToolTipText("Filter by any column (Host, Method, URL, Status, etc.)");
        filterPanel.add(new JLabel("Filter:"), BorderLayout.WEST);
        filterPanel.add(filterField, BorderLayout.CENTER);

        // Button panel for multiple buttons
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 5, 0));
        clearButton = new JButton("Clear History");
        importButton = new JButton("Import XML");
        buttonPanel.add(importButton);
        buttonPanel.add(clearButton);
        filterPanel.add(buttonPanel, BorderLayout.EAST);

        // Table selection listener
        viewer = new RequestResponseViewer(callbacks, helpers);
        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int row = table.getSelectedRow();
                if (row != -1) {
                    int modelRow = table.convertRowIndexToModel(row);
                    BurpEntry entry = tableModel.getEntry(modelRow);
                    viewer.setRequestResponse(entry);
                } else {
                    viewer.clear();
                }
            }
        });

        // Debounced universal filter logic
        filterField.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e) { scheduleFilter(); }
            public void removeUpdate(DocumentEvent e) { scheduleFilter(); }
            public void changedUpdate(DocumentEvent e) { scheduleFilter(); }
        });

        // Clear history logic
        clearButton.addActionListener(e -> {
            tableModel.clear();
            allEntries.clear();
            viewer.clear();
        });

        // Import XML logic
        importButton.addActionListener(e -> {
            JFileChooser chooser = new JFileChooser();
            int result = chooser.showOpenDialog(this);
            if (result == JFileChooser.APPROVE_OPTION) {
                File xmlFile = chooser.getSelectedFile();
                importXmlFile(xmlFile);
            }
        });

        // Double-click row to show request/response in viewer only
        table.addMouseListener(new MouseAdapter() {
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2 && SwingUtilities.isLeftMouseButton(e)) {
                    int row = table.rowAtPoint(e.getPoint());
                    if (row != -1) {
                        int modelRow = table.convertRowIndexToModel(row);
                        BurpEntry entry = tableModel.getEntry(modelRow);
                        viewer.setRequestResponse(entry);
                    }
                }
            }
        });

        // Right-click context menu for Send to Repeater/Intruder
        JPopupMenu popupMenu = new JPopupMenu();

        JMenuItem sendToRepeater = new JMenuItem("Send to Repeater");
        sendToRepeater.addActionListener(e -> {
            int row = table.getSelectedRow();
            if (row != -1) {
                int modelRow = table.convertRowIndexToModel(row);
                BurpEntry entry = tableModel.getEntry(modelRow);
                boolean isHttps = entry.isHttps();
                callbacks.sendToRepeater(
                    entry.getHost(),
                    entry.getPort(),
                    isHttps,
                    entry.getRequest(),
                    "From XML Parser"
                );
            }
        });

        JMenuItem sendToIntruder = new JMenuItem("Send to Intruder");
        sendToIntruder.addActionListener(e -> {
            int row = table.getSelectedRow();
            if (row != -1) {
                int modelRow = table.convertRowIndexToModel(row);
                BurpEntry entry = tableModel.getEntry(modelRow);
                boolean isHttps = entry.isHttps();
                callbacks.sendToIntruder(
                    entry.getHost(),
                    entry.getPort(),
                    isHttps,
                    entry.getRequest()
                );
            }
        });

        popupMenu.add(sendToRepeater);
        popupMenu.add(sendToIntruder);

        table.setComponentPopupMenu(popupMenu);

        JScrollPane tableScroll = new JScrollPane(table);
        tableScroll.setPreferredSize(new Dimension(900, 250));

        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, viewer);
        splitPane.setResizeWeight(0.4);

        add(filterPanel, BorderLayout.NORTH);
        add(splitPane, BorderLayout.CENTER);
    }

    // Debounced filter: matches text in any column, case-insensitive, no caret bug
    private void scheduleFilter() {
        if (filterTimer != null && filterTimer.isRunning()) {
            filterTimer.restart();
        } else {
            filterTimer = new Timer(150, evt -> {
                filter();
                filterTimer.stop();
            });
            filterTimer.setRepeats(false);
            filterTimer.start();
        }
    }

    private void filter() {
        String text = filterField.getText();
        if (text.length() == 0) {
            sorter.setRowFilter(null);
        } else {
            sorter.setRowFilter(new RowFilter<BurpHistoryTableModel, Integer>() {
                public boolean include(Entry<? extends BurpHistoryTableModel, ? extends Integer> entry) {
                    for (int i = 0; i < entry.getValueCount(); i++) {
                        Object val = entry.getValue(i);
                        if (val != null && val.toString().toLowerCase().contains(text.toLowerCase())) {
                            return true;
                        }
                    }
                    return false;
                }
            });
        }
    }

    // Add an entry programmatically (for demonstration/testing)
    public void addEntry(BurpEntry entry) {
        tableModel.addEntry(entry);
        allEntries.add(entry);
    }

    // --- XML Import Functionality ---
    private void importXmlFile(File xmlFile) {
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document doc = builder.parse(xmlFile);
            NodeList items = doc.getElementsByTagName("item");
            int imported = 0;
            for (int i = 0; i < items.getLength(); i++) {
                Element item = (Element) items.item(i);
                String host = getFirstTag(item, "host");
                String ip = "";
                NodeList hostNodes = item.getElementsByTagName("host");
                if (hostNodes.getLength() > 0 && hostNodes.item(0) instanceof Element) {
                    Element hostElem = (Element)hostNodes.item(0);
                    ip = hostElem.hasAttribute("ip") ? hostElem.getAttribute("ip") : "";
                }
                String url = getFirstTag(item, "url");
                String method = getFirstTag(item, "method");
                String statusStr = getFirstTag(item, "status");
                int status = statusStr.isEmpty() ? 0 : Integer.parseInt(statusStr);
                String reqBase64 = getFirstTag(item, "request");
                String respBase64 = getFirstTag(item, "response");
                byte[] req = java.util.Base64.getDecoder().decode(reqBase64);
                byte[] resp = java.util.Base64.getDecoder().decode(respBase64);
                int port = 80; // Default; parse port if present
                String portStr = getFirstTag(item, "port");
                if (!portStr.isEmpty()) {
                    try { port = Integer.parseInt(portStr); } catch (NumberFormatException ignore) {}
                }
                boolean https = url.startsWith("https");
                int length = resp.length;
                String mimeType = getFirstTag(item, "mimetype");

                BurpEntry entry = new BurpEntry(method, url, host, port, https, req, resp, status, length, mimeType, ip);
                addEntry(entry);
                imported++;
            }
            JOptionPane.showMessageDialog(this, "Imported " + imported + " entries.");
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Error importing: " + ex.getMessage());
            ex.printStackTrace();
        }
    }

    private String getFirstTag(Element elem, String tag) {
        NodeList nl = elem.getElementsByTagName(tag);
        if (nl.getLength() > 0) return nl.item(0).getTextContent();
        return "";
    }
}
