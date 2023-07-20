package org.mintaka5;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.mintaka5.ui.PGPWindow;

import java.io.IOException;
import java.security.Security;

public class Main {
    public static void main(String[] args) throws PGPException, IOException {
        Security.addProvider(new BouncyCastleProvider());

        new PGPWindow();
    }
}
