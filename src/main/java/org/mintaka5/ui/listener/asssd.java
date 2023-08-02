package org.mintaka5.ui.listener;

import org.mintaka5.ui.PGPWindow2;

import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;

public class IdentKeyListener implements KeyListener {
    private final PGPWindow2 mainWin;

    public IdentKeyListener(PGPWindow2 win) {
        mainWin = win;
    }
    @Override
    public void keyTyped(KeyEvent e) {

    }

    @Override
    public void keyPressed(KeyEvent e) {

    }

    @Override
    public void keyReleased(KeyEvent e) {
        mainWin.getGenKeyBtn().setEnabled((
                mainWin.getPasswdTxt().getPassword().length > 0 &&
                        !mainWin.getIdentTxt().getText().isEmpty()
        ));
    }
}
