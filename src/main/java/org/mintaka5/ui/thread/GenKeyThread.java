package org.mintaka5.ui.thread;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.mintaka5.crypto.ThingPGP;
import org.mintaka5.ui.PGPWindow2;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;

import static java.lang.System.out;

public class GenKeyThread extends Thread {
    private final PGPWindow2 mainWin;

    public GenKeyThread(PGPWindow2 pgpWin) {
        mainWin = pgpWin;
    }

    @Override
    public void run() {
        String ident = mainWin.getIdentTxt().getText().trim();
        char[] passwd = mainWin.getPasswdTxt().getPassword();

        out.println("starting key generation...");

        mainWin.getIdentTxt().setText("");
        mainWin.getPasswdTxt().setText("");
        mainWin.getGenKeyBtn().setEnabled(false);
        mainWin.getGenKeyBtn().setText("generating...");

        PGPKeyRingGenerator ring = null;
        try {
            ring = ThingPGP.generateKeyRing(ident, passwd);
            mainWin.setKeyRing(ring);
        } catch (PGPException e) {
            throw new RuntimeException("generation of keyrings failed. " + e.getMessage());
        }

        out.println("key generation has completed.");
        mainWin.getGenKeyBtn().setText("generate");
        // go back to main panel
        mainWin.getRootLayout().show(mainWin.getRootPanel(), PGPWindow2.SHOW_MAIN_PANEL);

        // store new keys in DB
        try {
            mainWin.storePublicKey(ring);
        } catch (NoSuchAlgorithmException | IOException e) {
            throw new RuntimeException(e);
        }

        try {
            join();
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
    }
}
