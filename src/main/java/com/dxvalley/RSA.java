package com.dxvalley;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.Enumeration;

/**
 * RSA class for cryptographic operations using the RSA algorithm.
 * The class supports encryption, decryption, digital signing, and signature verification.
 * <p>
 * Usage:
 * - Command-line execution: java RSA <keystore_path> <keystore_password> <alias> <operation> <message>
 * Supported operations: encrypt, decrypt, sign, verify
 * <p>
 * Operations:
 * - Encrypt: Encrypts a message using the RSA algorithm with PKCS1Padding.
 * - Decrypt: Decrypts an encrypted payload using the RSA algorithm with PKCS1Padding.
 * - Sign: Signs a payload using the SHA256withRSA algorithm.
 * - Verify: Verifies the signature of a payload using the SHA256withRSA algorithm.
 * <p>
 * Main Method:
 * - Reads command-line arguments to determine the operation, keystore information, and the message.
 * - Executes the specified operation and prints the result.
 * <p>
 * Note:
 * - Ensure that the keystore file contains a valid RSA key pair with the specified alias.
 * - Use this class as a reference for integrating RSA cryptography into your applications.
 *
 * @author Etana Alemu
 * @version 1.0
 * @since 30/12/2023
 */
public class RSA {

    // Class members for public and private keys.
    static PublicKey publicKey;
    static PrivateKey privateKey;
    /**
     * Main method for executing RSA cryptographic operations.
     *
     * @param args Command-line arguments: <keystore_path> <keystore_password> <alias> <operation> <message>
     */
    public static void main(String[] args) {
        String result = performRSAOperation(args);
        System.out.println(result);
    }

    /**
     * Perform RSA cryptographic operations and return the result.
     *
     * @param args Command-line arguments: <keystore_path> <keystore_password> <alias> <operation> <message>
     * @return The result of the operation as a String.
     */
    public static String performRSAOperation(String[] args) {

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
            loadKeystore(keystorePath, keystorePassword, alias);

            switch (operation) {
                case "encrypt":
                    // Encrypt the message
                    String encryptedMessage = encrypt(payload);
                    System.out.println("Encrypted Message: " + encryptedMessage);
                    return encryptedMessage;
                case "decrypt":
                    // Decrypt the message
                    String decryptedMessage = decrypt(payload);
                    System.out.println("Decrypted Message: " + decryptedMessage);
                    return decryptedMessage;
                case "sign":
                    // Sign the payload
                    byte[] signedPayload = signPayload(payload);
                    System.out.println("Signature: " + Base64.getEncoder().encodeToString(signedPayload));
                    return Base64.getEncoder().encodeToString(signedPayload);
                case "verify":
                    // Verify the signature
                    boolean verified = verifyPayload(Base64.getDecoder().decode(payload), payload);
                    System.out.println("Signature is " + (verified ? "valid" : "invalid"));
                    return verified ? "valid" : "invalid";
                default:
                    System.out.println("Invalid operation. Supported operations: encrypt, decrypt, sign, verify");
                    return "Invalid operation. Supported operations: encrypt, decrypt, sign, verify";
            }
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
                 IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
            return "Error during cryptographic operation: " + e.getMessage();
        } catch (Exception e) {
            e.printStackTrace();
            return "Unexpected error: " + e.getMessage();
        }
    }

    /**
     * Encrypts a message using the RSA algorithm with PKCS1Padding.
     *
     * @param message The message to be encrypted.
     * @return The Base64-encoded encrypted message.
     * @throws NoSuchAlgorithmException  If the specified algorithm is not available.
     * @throws NoSuchPaddingException    If the specified padding scheme is not available.
     * @throws InvalidKeyException       If the provided key is invalid.
     * @throws IllegalBlockSizeException If the block size is not supported by the cipher.
     * @throws BadPaddingException       If the padding is incorrect.
     */
    private static String encrypt(String message) throws NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return Base64.getEncoder().encodeToString(cipher.doFinal(message.getBytes()));

    }

    /**
     * Decrypts an encrypted payload using the RSA algorithm with PKCS1Padding.
     *
     * @param payload The Base64-encoded encrypted payload.
     * @return The decrypted message.
     * @throws NoSuchAlgorithmException  If the specified algorithm is not available.
     * @throws NoSuchPaddingException    If the specified padding scheme is not available.
     * @throws InvalidKeyException       If the provided key is invalid.
     * @throws IllegalBlockSizeException If the block size is not supported by the cipher.
     * @throws BadPaddingException       If the padding is incorrect.
     */
    private static String decrypt(String payload) throws NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        byte[] decodedMessage = Base64.getDecoder().decode(payload);
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = cipher.doFinal(decodedMessage);
        return new String(decryptedBytes);

    }

    /**
     * Verifies the signature of a payload using the SHA256withRSA algorithm.
     *
     * @param signedPayload The Base64-encoded signature.
     * @param payload       The payload to be verified.
     * @return True if the signature is valid; otherwise, false.
     * @throws NoSuchAlgorithmException If the specified algorithm for the signature is not available.
     * @throws InvalidKeyException      If the public key is invalid for signature verification.
     * @throws SignatureException       If an error occurs during signature verification.
     */
    private static boolean verifyPayload(byte[] signedPayload, String payload)
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(publicKey);
        verifier.update(payload.getBytes());
        return verifier.verify(signedPayload);

    }

    /**
     * Signs a payload using the SHA256withRSA algorithm.
     *
     * @param payload The payload to be signed.
     * @return The Base64-encoded signature.
     * @throws NoSuchAlgorithmException If the specified algorithm for the signature is not available.
     * @throws InvalidKeyException      If the private key is invalid for payload signing.
     * @throws SignatureException       If an error occurs during payload signing.
     */
    private static byte[] signPayload(String payload)
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(payload.getBytes());
        return signature.sign();

    }

    /**
     * Loads the keystore and retrieves public and private keys.
     *
     * @param keystorePath     The path to the keystore file.
     * @param keystorePassword The password for the keystore.
     * @param alias            The alias of the key pair in the keystore.
     * @throws IOException               If an I/O error occurs.
     * @throws NoSuchAlgorithmException  If the specified algorithm for the keystore is not available.
     * @throws CertificateException      If there is a problem with a certificate.
     * @throws KeyStoreException         If there is an issue with the keystore.
     * @throws UnrecoverableKeyException If the key cannot be recovered from the keystore.
     */
    private static void loadKeystore(String keystorePath, String keystorePassword, String alias)
            throws IOException, NoSuchAlgorithmException, CertificateException, KeyStoreException, UnrecoverableKeyException {
        FileInputStream keystoreStream = new FileInputStream(keystorePath);
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
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

        keystoreStream.close();
    }
}
