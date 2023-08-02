package org.mintaka5.ui.listener;

import org.mintaka5.ui.PGPWindow2;
import org.mintaka5.ui.thread.GenKeyThread;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

public class GenKeyButtonListener implements ActionListener {
    private PGPWindow2 mainWin;

    public GenKeyButtonListener(PGPWindow2 pgpWin) {
        mainWin = pgpWin;
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        GenKeyThread genThread = new GenKeyThread(mainWin);
        genThread.start();
    }
}
