package org.mintaka5.crypto;

import org.bouncycastle.bcpg.*;
import org.bouncycastle.bcpg.sig.Features;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.bc.BcPGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.*;
import org.bouncycastle.util.io.Streams;

import java.io.*;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Date;
import java.util.Iterator;

/**
 * Utility class for creating, storing, and using PGP keys for signing,
 * encryption, and decryption
 */
public class ThingPGP {
    /**
     *
     * @param ring secret key ring
     * @param out file that will store the secret key
     * @param armored whether to output file as ASCII armor or not
     */
    public static Path exportSecretKey(PGPSecretKeyRing ring, File out, boolean armored) throws IOException {
        if(armored) {
            ArmoredOutputStream aos = new ArmoredOutputStream(new BufferedOutputStream(new FileOutputStream(out)));
            ring.encode(aos);
            aos.close();
        } else {
            FileOutputStream fos = new FileOutputStream(out);
            ring.encode(fos);
            fos.close();
        }

        return Path.of(out.toURI());
    }

    /**
     *
     * @param id usually an email or some unique user-generated string
     * @param passwd password to protect secret keys
     * @return the keyring derived from the generator
     */
    public static PGPKeyRingGenerator generateKeyRing(String id, char[] passwd) throws PGPException {
        int s2kCount = 0xc0;

        RSAKeyPairGenerator kpg = new RSAKeyPairGenerator();
        kpg.init(
                new RSAKeyGenerationParameters(
                        BigInteger.valueOf(0x10001),
                        new SecureRandom(),
                        4096,
                        16
                )
        );

        // create master signing key
        PGPKeyPair rsaSign = new BcPGPKeyPair(PGPPublicKey.RSA_SIGN, kpg.generateKeyPair(), new Date());
        // create an encryption subkey
        PGPKeyPair rsaEnc = new BcPGPKeyPair(PGPPublicKey.RSA_ENCRYPT, kpg.generateKeyPair(), new Date());

        // add self-signature on the ID
        PGPSignatureSubpacketGenerator signingHash = new PGPSignatureSubpacketGenerator();

        // add signed metadata to the signature
        // 1) declare its purpose
        signingHash.setKeyFlags(false, KeyFlags.SIGN_DATA | KeyFlags.CERTIFY_OTHER);

        // 2) set preferences for secondary crypto algorithms to use when sending
        // messages to this key.
        signingHash.setPreferredSymmetricAlgorithms(false, new int[] {
                SymmetricKeyAlgorithmTags.AES_256,
                SymmetricKeyAlgorithmTags.AES_192,
                SymmetricKeyAlgorithmTags.AES_128
        });
        signingHash.setPreferredHashAlgorithms(false, new int[] {
                HashAlgorithmTags.SHA256,
                HashAlgorithmTags.SHA1,
                HashAlgorithmTags.SHA384,
                HashAlgorithmTags.SHA512,
                HashAlgorithmTags.SHA224
        });

        // 3) request that senders add additional checksums to the message
        // (useful for when verifying unsigned messages
        signingHash.setFeature(false, Features.FEATURE_MODIFICATION_DETECTION);

        // create a signature on the encryption subkey
        PGPSignatureSubpacketGenerator encHash = new PGPSignatureSubpacketGenerator();
        // add the metadata to declare its purpose
        encHash.setKeyFlags(false, KeyFlags.ENCRYPT_COMMS | KeyFlags.ENCRYPT_STORAGE);

        // objects used to encrypt the secret key
        PGPDigestCalculator sha1Calc = new BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1);
        PGPDigestCalculator sha256Calc = new BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA256);

        // protect it!!!
        PBESecretKeyEncryptor pske = (new BcPBESecretKeyEncryptorBuilder(
                PGPEncryptedData.AES_256,
                sha256Calc,
                s2kCount
        )).build(passwd);

        // finally, create the keyring itself
        PGPKeyRingGenerator krGen = new PGPKeyRingGenerator(
                PGPSignature.POSITIVE_CERTIFICATION,
                rsaSign,
                id,
                sha1Calc,
                signingHash.generate(),
                null,
                new BcPGPContentSignerBuilder(
                        rsaSign.getPublicKey().getAlgorithm(),
                        HashAlgorithmTags.SHA1
                ),
                pske
        );
        krGen.addSubKey(rsaEnc, encHash.generate(), null);

        return krGen;
    }

    /**
     *
     * @param ring generator that provides the key ring needed
     * @param out output file
     * @param armored ASCII armored or not?
     */
    public static Path exportPublicKey(PGPPublicKeyRing ring, File out, boolean armored) throws IOException {
        if(armored) {
            ArmoredOutputStream aos = new ArmoredOutputStream(new BufferedOutputStream(new FileOutputStream(out)));
            ring.encode(aos);
            aos.flush();
            aos.close();
        } else {
            FileOutputStream fos = new FileOutputStream(out);
            ring.encode(fos);
            fos.flush();
            fos.close();
        }

        return Path.of(out.toURI());
    }

    /**
     *
     * @param inFile input file
     * @return the public keyring derived from armored input file, needed for encrypting
     */
    public static PGPPublicKeyRing importPublicKeyring(File inFile) throws IOException {
        byte[] in = Files.readAllBytes(inFile.toPath());
        ArmoredInputStream ais = new ArmoredInputStream(new ByteArrayInputStream(in));

        return new PGPPublicKeyRing(ais, new JcaKeyFingerprintCalculator());
    }

    public static PGPSecretKeyRing importSecretKeyring(File inFile) throws IOException, PGPException {
        byte[] in = Files.readAllBytes(inFile.toPath());
        ArmoredInputStream ais = new ArmoredInputStream(new ByteArrayInputStream(in));

        BcPGPSecretKeyRingCollection ringCollection = new BcPGPSecretKeyRingCollection(PGPUtil.getDecoderStream(ais));
        Iterator<PGPSecretKeyRing> secRings = ringCollection.getKeyRings();

        return secRings.next();
    }

    /**
     *
     * @param ring the public keyring
     * @return the public key needed for encryption
     */
    public static PGPPublicKey getEncryptionKey(PGPPublicKeyRing ring) throws PGPException {
        Iterator<PGPPublicKey> keys = ring.getPublicKeys();

        while(keys.hasNext()) {
            PGPPublicKey k = keys.next();

            if(k.isEncryptionKey()) {
                return k;
            };
        }

        throw new PGPException("no encryption key found in the public key ring.");
    }

    /**
     *
     * @param ring generated keyring
     * @param pubKeyId the public key id
     * @param passwd password needed for extracting the secret key
     * @return the private key needed for decryption
     */
    public static PGPPrivateKey getDecryptionKey(PGPSecretKeyRing ring, long pubKeyId, String passwd) throws PGPException {
        Iterator<PGPSecretKey> keys = ring.getSecretKeys();

        while(keys.hasNext()) {
            PGPSecretKey sk = keys.next();

            if(sk.getKeyID() == pubKeyId) {
                return sk.extractPrivateKey(
                        new JcePBESecretKeyDecryptorBuilder().setProvider("BC")
                                .build(passwd.toCharArray())
                );
            }
        }

        throw new PGPException("no corresponding private key found for supplied ID");
    }

    /**
     *
     * @param key public key
     * @param data raw data
     * @return byte data
     */
    public static byte[] encrypt(PGPPublicKey key, byte[] data) throws IOException, PGPException {
        ByteArrayOutputStream encOut = new ByteArrayOutputStream();
        byte[] compressedData = compress(data);

        PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(
                new JcePGPDataEncryptorBuilder(PGPEncryptedData.CAST5)
                        .setWithIntegrityPacket(true)
                        .setSecureRandom(new SecureRandom())
                        .setProvider("BC")
        );
        encGen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(key).setProvider("BC"));

        ArmoredOutputStream aOut = new ArmoredOutputStream(encOut);
        OutputStream cOut = encGen.open(aOut, compressedData.length);
        cOut.write(compressedData);
        cOut.close();
        aOut.close();

        return encOut.toByteArray();
    }

    /**
     *
     * @param key private key
     * @param data raw data
     * @return byte data
     */
    public static byte[] decrypt(PGPPrivateKey key, byte[] data) throws Exception {
        InputStream in = PGPUtil.getDecoderStream(new ByteArrayInputStream(data));
        JcaPGPObjectFactory pgpF = new JcaPGPObjectFactory(in);

        PGPEncryptedDataList enc;

        Object o = pgpF.nextObject();
        if(o instanceof PGPEncryptedDataList) {
            enc = (PGPEncryptedDataList) o;
        } else {
            enc = (PGPEncryptedDataList) pgpF.nextObject();
        }

        Iterator<PGPEncryptedData> it = enc.getEncryptedDataObjects();
        PGPPublicKeyEncryptedData pbe = null;

        while(it.hasNext()) {
            pbe = (PGPPublicKeyEncryptedData) it.next();
        }

        InputStream clear = pbe.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(key));
        JcaPGPObjectFactory plainF = new JcaPGPObjectFactory(clear);
        PGPCompressedData cData = (PGPCompressedData) plainF.nextObject();
        plainF = new JcaPGPObjectFactory(cData.getDataStream());
        PGPLiteralData ld = (PGPLiteralData) plainF.nextObject();

        return Streams.readAll(ld.getInputStream());
    }

    /**
     *
     * @param data raw data
     * @return compressed byte data
     */
    private static byte[] compress(byte[] data) throws IOException {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(CompressionAlgorithmTags.ZIP);
        OutputStream cos = comData.open(bOut);

        PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();
        OutputStream pOut = lData.open(cos, PGPLiteralData.BINARY, PGPLiteralData.CONSOLE, data.length, new Date());
        pOut.write(data);
        pOut.close();

        comData.close();

        return bOut.toByteArray();
    }

    public static PGPPublicKeyRing decodePublicRing(byte[] b) throws IOException {
        ByteArrayInputStream i = new ByteArrayInputStream(b);
        PGPObjectFactory f = new JcaPGPObjectFactory(PGPUtil.getDecoderStream(i));

        return (PGPPublicKeyRing) f.nextObject();
    }

    public static byte[] makeArmoredMessage(byte[] data) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ArmoredOutputStream aos = new ArmoredOutputStream(bos);
        aos.write(data);
        aos.flush();
        aos.close();

        return bos.toByteArray();
    }
}