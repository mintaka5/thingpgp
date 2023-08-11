package org.mintaka5.console;

import org.apache.commons.cli.*;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.mintaka5.crypto.ThingPGP;
import org.mintaka5.util.Utilities;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.*;

import static java.lang.System.out;

public class PGPCommandLine {

    public PGPCommandLine(String[] args) {
        Security.addProvider(new BouncyCastleProvider());

        Options options = setupOptions();

        parseCommands(options, args);
    }

    private void parseCommands(Options options, String[] args) {
        CommandLineParser parser = new DefaultParser();
        try {
            CommandLine line = parser.parse(options, args);

            HelpFormatter helpF = new HelpFormatter();

            /**
             * @TODO
             * condense this into a method or class TOO MUCH TUNA!!!
             */

            if(line.hasOption("h")) {
                helpF.printHelp("thingpgp", "ThingPGP\n\n", options, "\ncontact: chris.is.rad@pm.me");
            }

            if (line.hasOption("g") && line.getOptionValues("g").length == 3) {
                String[] argsA = line.getOptionValues("g");
                handleGen(argsA[0].trim(), argsA[1].trim().toCharArray(), Paths.get(argsA[2].trim()));
            }

            if(line.hasOption("d") && line.getOptionValues("d").length == 3) {
                String[] argsB = line.getOptionValues("d");
                handleDecryption(argsB);
            }

            if(line.hasOption("e") && line.getOptionValues("e").length == 2) {
                String[] argsB = line.getOptionValues("e");
                /**
                 * grab input strings from command line argument directives.
                 */
                String inputS = (String) argsB[1].trim().replaceAll("\\\\", "/");
                String pubS = (String) argsB[0].trim().replaceAll("\\\\", "/");

                PGPPublicKey pubKey = null;
                /**
                 * check to see if the user input provided for argument index 0
                 * is a valid path to an armored public key file.
                 */
                if(Utilities.isValidPath(pubS)) {
                    // a valid file was provided
                    PGPPublicKeyRing pubRing = ThingPGP.importPublicKeyring(Paths.get(pubS).toFile());
                    pubKey = ThingPGP.getEncryptionKey(pubRing);
                }

                // if pub key was successfully pulled from file, go...
                if(pubKey != null) {
                    /**
                     * if the input of argument index 1 is a valid file path
                     * then we are dealing with a file obviously, or it's something
                     * else, but for now that something else is a string.
                     */
                    final String tmpOutS = "%s encryption:\n\nsignature: %s\n\nencrypted message\n%s\n";
                    if (Utilities.isValidPath(inputS)) {
                        // we got a file. handle it
                        byte[] encMsg = handleFileEncryption(pubKey, Files.readAllBytes(Paths.get(inputS)));
                        byte[] armoredMsg = ThingPGP.makeArmoredMessage(encMsg);
                        out.printf(tmpOutS,
                                "file",
                                Hex.encodeHexString(MessageDigest.getInstance("SHA-256").digest(armoredMsg)),
                                new String(armoredMsg)
                        );
                    } else {
                        // it's a random string of data or something else spooky.
                        byte[] encStr = handleStringEncryption(pubKey, inputS.getBytes());
                        byte[] armoredStr = ThingPGP.makeArmoredMessage(encStr);
                        out.printf(tmpOutS,
                                "string",
                                Hex.encodeHexString(MessageDigest.getInstance("SHA-256").digest(armoredStr)),
                                new String(armoredStr)
                        );
                    }
                }
            }
        } catch (ParseException e) {
            out.println("parsing failed. reason: " + e.getMessage());
        } catch (IOException e) {
            throw new RuntimeException("failed to import public key ring. " + e.getMessage());
        } catch (PGPException e) {
            throw new RuntimeException("failed to acquire public key from key ring. " + e.getMessage());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private void handleDecryption(String[] args) {
        /**
         * what we need is private key from secret keyring,
         * the encrypted message, and password
         */
        String secKey = args[0].trim().replaceAll("\\\\", "/");
        String encMsg = args[1].trim().replaceAll("\\\\", "/");
        String passwd = args[2].trim();

        /**
         * check args 0 and 1 to see if they are files or not.
         * user can supply an armored ascii file or a base64 string
         * @TODO make a way to export these
         */
        PGPSecretKeyRing skRing = null;
        PGPPrivateKey privKey = null;

        if(Utilities.isValidPath(secKey)) { // we've got a file
            try {
                skRing = ThingPGP.importSecretKeyring(Paths.get(secKey).toFile());
                privKey = ThingPGP.getDecryptionKey(skRing, skRing.getPublicKey().getKeyID(), passwd);

            } catch (IOException | PGPException e) {
                throw new RuntimeException("failed to import secret key ring. check that file is a valid armored ascii file. " + e.getMessage());
            }
        }
    }

    private Options setupOptions() {
        HashMap<String, Option> o = new HashMap<>();

        Option genOpt = Option.builder("g")
                .longOpt("generate")
                .desc("generate a new key. "
                        .concat("usage: thingpgp -g | --generate <identity> <password> <path/to/save/directory>"))
                .required(false)
                .numberOfArgs(3)
                .hasArgs()
                .build();
        o.put("GEN", genOpt);

        Option encOpt = Option.builder("e")
                .longOpt("encrypt")
                .desc("encrypt a message, file, or in general byte data. "
                        .concat("usage: thingpgp -e"))
                .numberOfArgs(2)
                .required(false)
                .hasArgs()
                .build();
        o.put("ENC", encOpt);

        Option decOpt = Option.builder("d")
                .longOpt("decrypt")
                .desc("decrypt a message, file, or in general byte data. ".concat("usages: thingpgp -d"))
                .hasArgs()
                .numberOfArgs(3)
                .build();
        o.put("DEC", decOpt);

        Option helpOpt = Option.builder("h").longOpt("help")
                .build();
        o.put("HELP", helpOpt);

        Options opts = new Options();
        o.forEach((k, v) -> opts.addOption(v));

        return opts;
    }

    private byte[] handleStringEncryption(PGPPublicKey pub, byte[] b) {
        try {
            return ThingPGP.encrypt(pub, b);
        } catch (PGPException e) {
            throw new RuntimeException("failed to encrypt data. " + e.getMessage());
        } catch (IOException e) {
            throw new RuntimeException("invalid byte data was provided. " + e);
        }
    }

    private byte[] handleFileEncryption(PGPPublicKey pk, byte[] d) {
        try {
            return ThingPGP.encrypt(pk, d);
        } catch (IOException | PGPException e) {
            throw new RuntimeException(e);
        }
    }

    private void handleGen(String ident, char[] passwd, Path p) {
        out.println("key generating happening...");
        if (!Files.exists(p)) {
            try {
                Files.createDirectories(p);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        try {
            PGPKeyRingGenerator gen = ThingPGP.generateKeyRing(ident, passwd);

            Path pubP = Path.of(p.toString(), "pub.asc");
            Path secP = Path.of(p.toString(), "sec.asc");

            Path newSecP = ThingPGP.exportSecretKey(gen.generateSecretKeyRing(), secP.toFile(), true);
            Path newPubP = ThingPGP.exportPublicKey(gen.generatePublicKeyRing(), pubP.toFile(), true);
            out.printf("saved keys to file: [pub: %s; sec: %s]\r\n", newPubP, newSecP);
        } catch (PGPException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static void main(String[] args) {
        new PGPCommandLine(args);
    }
}
