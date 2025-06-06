package burp;

import javax.swing.*;
import java.awt.*;

public class BurpExtender implements IBurpExtender, ITab {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private BurpHistoryPanel historyPanel;

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();

        // Print credits to the Extender > Output tab
        callbacks.setExtensionName("BurpXtract");
        callbacks.printOutput("BurpXtract Loaded");
        callbacks.printOutput("Concept & Design: Turbanator aka Gurjot Singh");
        callbacks.printOutput("Developed With Help From: AI Agents");

        SwingUtilities.invokeLater(() -> {
            historyPanel = new BurpHistoryPanel(callbacks, helpers);
            callbacks.customizeUiComponent(historyPanel);
            callbacks.addSuiteTab(BurpExtender.this);
            // Removed: callbacks.registerContextMenuFactory(historyPanel);
        });
    }

    @Override
    public String getTabCaption() {
        return "BurpXtract";
    }

    @Override
    public Component getUiComponent() {
        return historyPanel;
    }
}
