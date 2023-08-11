package org.mintaka5;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.mintaka5.ui.PGPWindow2;

import java.io.IOException;
import java.security.Security;
import java.util.concurrent.ExecutionException;

public class Main {
    public static void main(String[] args) throws IOException, ExecutionException, InterruptedException {
        Security.addProvider(new BouncyCastleProvider());

        // new PGPWindow();
        new PGPWindow2();
    }
}
