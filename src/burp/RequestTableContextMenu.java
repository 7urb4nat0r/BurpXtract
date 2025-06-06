package burp;

import burp.IExtensionHelpers;
import burp.IBurpExtenderCallbacks;

import javax.swing.*;
import java.awt.event.*;

public class RequestTableContextMenu {
    private final JTable requestTable;
    private final IExtensionHelpers helpers;
    private final IBurpExtenderCallbacks callbacks;

    public RequestTableContextMenu(JTable requestTable, IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks) {
        this.requestTable = requestTable;
        this.helpers = helpers;
        this.callbacks = callbacks;
        addContextMenu();
        addDoubleClickToRepeater();
    }

    private void addContextMenu() {
        JPopupMenu popupMenu = new JPopupMenu();

        JMenuItem sendToRepeater = new JMenuItem("Send to Repeater");
        JMenuItem sendToIntruder = new JMenuItem("Send to Intruder");

        sendToRepeater.addActionListener(e -> sendSelectedRowToBurpTool(BurpTool.REPEATER));
        sendToIntruder.addActionListener(e -> sendSelectedRowToBurpTool(BurpTool.INTRUDER));

        popupMenu.add(sendToRepeater);
        popupMenu.add(sendToIntruder);

        requestTable.setComponentPopupMenu(popupMenu);
    }

    private void addDoubleClickToRepeater() {
        requestTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2 && SwingUtilities.isLeftMouseButton(e)) {
                    int row = requestTable.rowAtPoint(e.getPoint());
                    if (row != -1) {
                        requestTable.setRowSelectionInterval(row, row);
                        sendSelectedRowToBurpTool(BurpTool.REPEATER);
                    }
                }
            }
        });
    }

    private enum BurpTool { REPEATER, INTRUDER }

    private void sendSelectedRowToBurpTool(BurpTool tool) {
        int row = requestTable.getSelectedRow();
        if (row == -1) return;

        // Adjust these indices if your table columns are arranged differently
        String host = (String) requestTable.getValueAt(row, 1);
        int port = Integer.parseInt(requestTable.getValueAt(row, 2).toString());
        String protocol = (String) requestTable.getValueAt(row, 3);
        byte[] requestBytes = (byte[]) requestTable.getValueAt(row, 4);

        boolean useHttps = "https".equalsIgnoreCase(protocol);

        switch (tool) {
            case REPEATER:
                callbacks.sendToRepeater(host, port, useHttps, requestBytes, "From XML Parser");
                break;
            case INTRUDER:
                callbacks.sendToIntruder(host, port, useHttps, requestBytes);
                break;
        }
    }
}
