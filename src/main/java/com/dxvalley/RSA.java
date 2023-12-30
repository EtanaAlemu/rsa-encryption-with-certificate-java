package com.dxvalley;

import javax.crypto.Cipher;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;
import java.util.Enumeration;

public class RSA {

    static PublicKey publicKey;
    static PrivateKey privateKey;
    private static final String KEYSTORE_PATH = "C:\\Users\\Appconpc\\IdeaProjects\\RSA\\card_management_keystore.p12";
    private static final String KEYSTORE_PASSWORD = "4bf5bdc900fbf6e6506be4b052bf2d99";
    private static final String ALIAS = "mobile_card_management";

    public static void main(String[] args) {
        try {
            // Message to be encrypted
            String payload = "{\"Pan\":\"D9946D7527EDD05E640\",\"NewPin\":\"89E598689DCF5437\",\"SkipFeeCheck\":true,\"KeyReference\":\"EMBOSSING_ZPK\",\"KeyType\":\"ZPK\",\"PinBlockFormat\":1,\"Reason\":\"TESTPINSET\",\"PinType\":1}";

            // Print results
            System.out.println("Original Message: " + payload);
            // Encrypt the message
            String encryptedMessage = encrypt(payload);

            System.out.println("Encrypted Message: " + encryptedMessage);
            // Decrypt the message
            String decryptedMessage = decrypt(encryptedMessage);
            System.out.println("Decrypted Message: " + decryptedMessage);

            byte[] signedPayload = signPayload(payload);

            boolean verified = verifyPayload(signedPayload, payload);
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

    public static String encrypt(String message) {
        try {
            loadKeystoreTrustStore();
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            return Base64.getEncoder().encodeToString(cipher.doFinal(message.getBytes()));
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static String decrypt(String payload) {
        try {
            loadKeystoreTrustStore();
            byte[] decodedMessage = Base64.getDecoder().decode(payload);
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decryptedBytes = cipher.doFinal(decodedMessage);
            return new String(decryptedBytes);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    // Verify the signature
    public static boolean verifyPayload(byte[] signedPayload, String payload) {
        try {
            loadKeystoreTrustStore();
            Signature verifier = Signature.getInstance("SHA256withRSA");
            verifier.initVerify(publicKey);
            verifier.update(payload.getBytes());
            return verifier.verify(signedPayload);
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    // Sign the payload
    public static byte[] signPayload(String payload) {
        try {
            loadKeystoreTrustStore();
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);
            signature.update(payload.getBytes());
            return signature.sign();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private static void loadKeystoreTrustStore() {
        try (FileInputStream keystoreStream = new FileInputStream(KEYSTORE_PATH)) {
            KeyStore keyStore = KeyStore.getInstance("PKCS12"); // Specify the provider
            keyStore.load(keystoreStream, KEYSTORE_PASSWORD.toCharArray());

            // Print all aliases in the keystore for debugging purposes
            Enumeration<String> aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {
                System.out.println("Alias: " + aliases.nextElement());
            }

            // Retrieve private and public keys from keystore
            privateKey = (PrivateKey) keyStore.getKey(ALIAS, KEYSTORE_PASSWORD.toCharArray());
            System.out.println("PrivateKey Algorithm: " + privateKey.getAlgorithm());
            System.out.println("PrivateKey Format: " + privateKey.getFormat());
            System.out.println("PrivateKey Encoded: " + Base64.getEncoder().encodeToString(privateKey.getEncoded()));

            publicKey = keyStore.getCertificate(ALIAS).getPublicKey();
            System.out.println("PublicKey Algorithm: " + publicKey.getAlgorithm());
            System.out.println("PublicKey Format: " + publicKey.getFormat());
            System.out.println("PublicKey Encoded: " + Base64.getEncoder().encodeToString(publicKey.getEncoded()));


        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
