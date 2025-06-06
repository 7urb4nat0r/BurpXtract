package burp;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

public class BurpHistoryTableModel extends AbstractTableModel {
    private final List<BurpEntry> entries = new ArrayList<>();
    private final String[] columns = {
        "No.", "Host", "Method", "URL", "Status", "Length", "MIME Type", "IP"
    };

    @Override
    public int getRowCount() {
        return entries.size();
    }

    @Override
    public int getColumnCount() {
        return columns.length;
    }

    @Override
    public String getColumnName(int col) {
        return columns[col];
    }

    @Override
    public Object getValueAt(int row, int col) {
        BurpEntry entry = entries.get(row);
        switch (col) {
            case 0: return row + 1; // No. as Integer for sorting
            case 1: return entry.getHost();
            case 2: return entry.getMethod();
            case 3: return entry.getUrl();
            case 4: return entry.getStatus();
            case 5: return entry.getLength();
            case 6: return entry.getMimeType();
            case 7: return entry.getIp();
            default: return "";
        }
    }

    public BurpEntry getEntry(int row) {
        return entries.get(row);
    }

    public void addEntry(BurpEntry entry) {
        entries.add(entry);
        fireTableRowsInserted(entries.size() - 1, entries.size() - 1);
    }

    public void clear() {
        int size = entries.size();
        entries.clear();
        if (size > 0) fireTableRowsDeleted(0, size - 1);
    }
}
