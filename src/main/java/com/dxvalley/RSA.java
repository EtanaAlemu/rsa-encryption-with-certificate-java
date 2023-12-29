package com.dxvalley;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Arrays;

public class RSA {

    static PublicKey publicKey;
    static PrivateKey privateKey;
    private static final String KEYSTORE_PATH = "C:\\Users\\Appconpc\\IdeaProjects\\RSA\\card_management_keystore.jks";
    private static final String TRUSTSTORE_PATH = "C:\\Users\\Appconpc\\IdeaProjects\\RSA\\card_management_truststore.jks";
    private static final String KEYSTORE_PASSWORD = "8e0d049a2b55426badd6e47005e52e2f";
    private static final String TRUSTSTORE_PASSWORD = "b6f810c59f6a9458d0bff69050bbd1f7";

    public static void main(String[] args) throws Exception {
        try {
        // Message to be encrypted
        String payload = "Hello, RSA!";

        // Encrypt the message
        byte[] encryptedBytes = encrypt(payload);

        // Decrypt the message
        String decryptedMessage = decrypt(encryptedBytes);

        // Print results
        System.out.println("Original Message: " + payload);
        System.out.println("Encrypted Message: " + new String(encryptedBytes));
        System.out.println("Decrypted Message: " + decryptedMessage);

        byte[] signedPayload = signPayload(payload);

        boolean verified = verifyPayload(signedPayload,payload);
        if (verified) {
            // Signature is valid
            System.out.println("valid");
        } else {
            // Signature is invalid
            System.out.println("invalid");
        }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static byte[] encrypt(String message) throws Exception {
        loadKeystoreTrustStore();
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(message.getBytes());
    }

    public static String decrypt(byte[] encryptedBytes) throws Exception {
        loadKeystoreTrustStore();
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        return new String(decryptedBytes);
    }

    // Verify the signature
    public static boolean verifyPayload(byte[] signedPayload, String payload) throws Exception{
            loadKeystoreTrustStore();
            Signature verifier = Signature.getInstance("SHA256withRSA");
            verifier.initVerify(publicKey);
            verifier.update(payload.getBytes());
            return verifier.verify(signedPayload);
    }

    // Sign the payload
    public static byte[] signPayload(String payload)throws Exception {
        loadKeystoreTrustStore();
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(payload.getBytes());
        return signature.sign();
    }

    private static void loadKeystoreTrustStore() throws Exception {
        // Load Bouncy Castle provider
        Security.addProvider(new BouncyCastleProvider());

        try (FileInputStream keystoreStream = new FileInputStream(KEYSTORE_PATH);
             FileInputStream truststoreStream = new FileInputStream(TRUSTSTORE_PATH)) {

            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(keystoreStream, KEYSTORE_PASSWORD.toCharArray());

            KeyStore trustStore = KeyStore.getInstance("JKS");
            trustStore.load(truststoreStream, TRUSTSTORE_PASSWORD.toCharArray());

            // Retrieve private and public keys from keystore
            privateKey = (PrivateKey) keyStore.getKey("mobile_card_management", KEYSTORE_PASSWORD.toCharArray());
            publicKey = trustStore.getCertificate("mobile_card_management").getPublicKey();
        } catch (FileNotFoundException e) {
            throw new FileNotFoundException("Keystore or truststore file not found. Check file paths.");
        }
    }
}
