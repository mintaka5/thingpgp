package org.mintaka5.ui.component;

import org.mintaka5.model.KeyRepo;

import javax.swing.*;
import java.awt.*;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

public class PubKeyListRenderer extends JLabel implements ListCellRenderer<KeyRepo> {
    @Override
    public Component getListCellRendererComponent(JList<? extends KeyRepo> list, KeyRepo value, int index, boolean isSelected, boolean cellHasFocus) {
        String hash = value.getHash();
        String date = DateTimeFormatter.ofPattern("YYYY-MM-dd HH:mm:ss").withZone(ZoneId.systemDefault()).format(Instant.ofEpochMilli(value.getTimestamp()));

        setOpaque(true);
        setText(date + "\r\n" + hash);
        setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

        if(cellHasFocus || isSelected) {
            setForeground(list.getSelectionForeground());
            setBackground(list.getSelectionBackground());
        } else {
            setForeground(list.getForeground());
            setBackground(list.getBackground());
        }

        return this;
    }
}
