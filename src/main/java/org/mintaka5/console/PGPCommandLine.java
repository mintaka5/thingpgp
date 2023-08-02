package org.mintaka5.console;

import org.apache.commons.cli.*;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.mintaka5.crypto.ThingPGP;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;

import static java.lang.System.out;

public class PGPCommandLine {

    public PGPCommandLine(String[] args) {
        Option genOpt = Option.builder("g")
                .longOpt("generate")
                .desc("generate a new key")
                .required(false)
                .numberOfArgs(3)
                .hasArgs()
                .build();
        Option encOpt = Option.builder("e")
                .longOpt("encrypt")
                .desc("encrypt a message, file, or in general byte data.")
                .numberOfArgs(2)
                .hasArgs()
                .build();

        Options opts = new Options();
        opts.addOption(genOpt);
        opts.addOption(encOpt);

        CommandLineParser parser = new DefaultParser();
        try {
            CommandLine line = parser.parse(opts, args);

            HelpFormatter helpF = new HelpFormatter();

            if(line.getOptions().length == 0) {
                helpF.printHelp("pgpcmd", opts);
            }

            /**
             * @TODO i want a switch!
             */

            if(line.hasOption("g")) {
                if(line.getOptionValues("g").length == 3) {
                    String[] argsA = line.getOptionValues("g");
                    handleGen(argsA[0].trim(), argsA[1].trim().toCharArray(), Paths.get(argsA[2].trim()));
                } else {
                    helpF.printHelp("pgpcmd", opts);
                }
            }
        } catch (ParseException e) {
            out.println("parsing failed. reason: " + e.getMessage());
        }
    }

    private void handleGen(String ident, char[] passwd, Path p) {
        if(!Files.exists(p)) {
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
