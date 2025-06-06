package burp;

import javax.swing.*;
import java.awt.*;

public class RequestResponseViewer extends JPanel {
    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private final IMessageEditor requestViewer;
    private final IMessageEditor responseViewer;
    private final JCheckBox wrapCheckBox;

    public RequestResponseViewer(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers) {
        super(new BorderLayout());
        this.callbacks = callbacks;
        this.helpers = helpers;

        // Message editors
        requestViewer = callbacks.createMessageEditor(null, false);
        responseViewer = callbacks.createMessageEditor(null, false);

        // Wrap text option
        wrapCheckBox = new JCheckBox("Wrap text");
        wrapCheckBox.addActionListener(e -> {
            setWrapText(requestViewer, wrapCheckBox.isSelected());
            setWrapText(responseViewer, wrapCheckBox.isSelected());
        });

        JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        topPanel.add(wrapCheckBox);

        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                requestViewer.getComponent(), responseViewer.getComponent());
        splitPane.setResizeWeight(0.5);

        add(topPanel, BorderLayout.NORTH);
        add(splitPane, BorderLayout.CENTER);
    }

    public void setRequestResponse(BurpEntry entry) {
        requestViewer.setMessage(entry.getRequest(), true);
        responseViewer.setMessage(entry.getResponse(), false);
    }

    public void clear() {
        requestViewer.setMessage(null, true);
        responseViewer.setMessage(null, false);
    }

    // Enable/disable wrap text (works for Burp's default editors, but may not affect raw hex view)
    private void setWrapText(IMessageEditor editor, boolean wrap) {
        Component comp = editor.getComponent();
        JTextArea textArea = findTextArea(comp);
        if (textArea != null) {
            textArea.setLineWrap(wrap);
            textArea.setWrapStyleWord(wrap);
            textArea.repaint();
        }
    }

    private JTextArea findTextArea(Component comp) {
        if (comp instanceof JTextArea) return (JTextArea) comp;
        if (comp instanceof Container) {
            for (Component child : ((Container) comp).getComponents()) {
                JTextArea area = findTextArea(child);
                if (area != null) return area;
            }
        }
        return null;
    }
}
