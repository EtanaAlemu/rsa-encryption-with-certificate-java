package com.dxvalley;

import javax.crypto.Cipher;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;
import java.util.Enumeration;
/**
 * RSA class for cryptographic operations using the RSA algorithm.
 * The class supports encryption, decryption, digital signing, and signature verification.
 *
 * Usage:
 * - Command-line execution: java RSA <keystore_path> <keystore_password> <alias> <operation> <message>
 *   Supported operations: encrypt, decrypt, sign, verify
 *
 * Operations:
 * - Encrypt: Encrypts a message using the RSA algorithm with PKCS1Padding.
 * - Decrypt: Decrypts an encrypted payload using the RSA algorithm with PKCS1Padding.
 * - Sign: Signs a payload using the SHA256withRSA algorithm.
 * - Verify: Verifies the signature of a payload using the SHA256withRSA algorithm.
 *
 * Main Method:
 * - Reads command-line arguments to determine the operation, keystore information, and the message.
 * - Executes the specified operation and prints the result.
 *
 * Note:
 * - Ensure that the keystore file contains a valid RSA key pair with the specified alias.
 * - Use this class as a reference for integrating RSA cryptography into your applications.
 *
 * @author [Etana Alemu]
 * @version 1.0
 * @since [30/12/2023]
 */
public class RSA {

    // Class members for public and private keys.
    static PublicKey publicKey;
    static PrivateKey privateKey;
    /**
     * Main method for executing RSA cryptographic operations.
     *
     * @param args Command-line arguments: <keystore_path> <keystore_password> <alias> <operation> <message>
     *             Supported operations: encrypt, decrypt, sign, verify
     */
    public static void main(String[] args) {

        if (args.length < 5) {
            System.out.println("Usage: java RSA <keystore_path> <keystore_password> <alias> <operation> <message>");
            System.exit(1);
        }

        String keystorePath = args[0];
        String keystorePassword = args[1];
        String alias = args[2];
        String operation = args[3].toLowerCase(); // Convert operation to lowercase for case-insensitivity
        String payload = args[4];

        try {

            System.out.println("Original Message: " + payload);
            loadKeystoreTrustStore(keystorePath, keystorePassword, alias);
            switch (operation) {
                case "encrypt":
                    // Encrypt the message
                    String encryptedMessage = encrypt(payload);
                    System.out.println("Encrypted Message: " + encryptedMessage);
                    break;
                case "decrypt":
                    // Decrypt the message
                    String decryptedMessage = decrypt(payload);
                    System.out.println("Decrypted Message: " + decryptedMessage);
                    break;
                case "sign":
                    // Sign the payload
                    byte[] signedPayload = signPayload(payload);
                    System.out.println("Signature: " + Base64.getEncoder().encodeToString(signedPayload));
                    break;
                case "verify":
                    // Verify the signature
                    boolean verified = verifyPayload(Base64.getDecoder().decode(payload), payload);
                    if (verified) {
                        // Signature is valid
                        System.out.println("Signature is valid");
                    } else {
                        // Signature is invalid
                        System.out.println("Signature is invalid");
                    }
                    break;
                default:
                    System.out.println("Invalid operation. Supported operations: encrypt, decrypt, sign, verify");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Encrypts a message using the RSA algorithm with PKCS1Padding.
     *
     * @param message The message to be encrypted.
     * @return The Base64-encoded encrypted message.
     */
    private static String encrypt(String message) {
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            return Base64.getEncoder().encodeToString(cipher.doFinal(message.getBytes()));
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Decrypts an encrypted payload using the RSA algorithm with PKCS1Padding.
     *
     * @param payload The Base64-encoded encrypted payload.
     * @return The decrypted message.
     */
    private static String decrypt(String payload) {
        try {
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
    /**
     * Verifies the signature of a payload using the SHA256withRSA algorithm.
     *
     * @param signedPayload The Base64-encoded signature.
     * @param payload       The payload to be verified.
     * @return True if the signature is valid; otherwise, false.
     */
    private static boolean verifyPayload(byte[] signedPayload, String payload) {
        try {
            Signature verifier = Signature.getInstance("SHA256withRSA");
            verifier.initVerify(publicKey);
            verifier.update(payload.getBytes());
            return verifier.verify(signedPayload);
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }
    /**
     * Signs a payload using the SHA256withRSA algorithm.
     *
     * @param payload The payload to be signed.
     * @return The Base64-encoded signature.
     */
    private static byte[] signPayload(String payload) {
        try {
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);
            signature.update(payload.getBytes());
            return signature.sign();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
    /**
     * Loads the keystore and retrieves public and private keys.
     *
     * @param keystorePath     The path to the keystore file.
     * @param keystorePassword The password for the keystore.
     * @param alias            The alias of the key pair in the keystore.
     */
    private static void loadKeystoreTrustStore(String keystorePath, String keystorePassword, String alias) {
        try (FileInputStream keystoreStream = new FileInputStream(keystorePath)) {
            KeyStore keyStore = KeyStore.getInstance("PKCS12"); // Specify the provider
            keyStore.load(keystoreStream, keystorePassword.toCharArray());

            // Print all aliases in the keystore for debugging purposes
            Enumeration<String> aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {
                System.out.println("Alias: " + aliases.nextElement());
            }

            // Retrieve private and public keys from keystore
            privateKey = (PrivateKey) keyStore.getKey(alias, keystorePassword.toCharArray());
            System.out.println("PrivateKey Algorithm: " + privateKey.getAlgorithm());
            System.out.println("PrivateKey Format: " + privateKey.getFormat());
            System.out.println("PrivateKey Encoded: " + Base64.getEncoder().encodeToString(privateKey.getEncoded()));

            publicKey = keyStore.getCertificate(alias).getPublicKey();
            System.out.println("PublicKey Algorithm: " + publicKey.getAlgorithm());
            System.out.println("PublicKey Format: " + publicKey.getFormat());
            System.out.println("PublicKey Encoded: " + Base64.getEncoder().encodeToString(publicKey.getEncoded()));


        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
