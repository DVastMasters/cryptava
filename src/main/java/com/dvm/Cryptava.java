package com.dvm;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Scanner;

/**
 * A simple algorithm to generate cryptography keys and encrypt/decrypt some
 * data.
 *
 * <p>
 * <b>Warning:</b> This implementation was made just for study the java.security
 * package. Don't use this for real purposes.
 * </p>
 */
public class Cryptava {
    private static String lineSeparator = System.lineSeparator();
    private static Scanner scanner = new Scanner(System.in);
    private static int option;

    public static void main(String[] args) {
        do {
            System.out.println(
                    "--- Options ---" + lineSeparator +
                            "1. Generate a RSA key pair (2048 bits)." + lineSeparator +
                            "2. Encrypt a file." + lineSeparator +
                            "3. Decrypt a file." + lineSeparator +
                            "0. Quit.");

            System.out.print("Choose a option: ");
            option = Integer.parseInt(scanner.nextLine());

            switch (option) {
                case 1:
                    generateKeyPair();
                    break;
                case 2:
                    encryptFile();
                    break;
                case 3:
                    decryptFile();
            }

        } while (option != 0);
    }

    public static void generateKeyPair() {
        String algorithm = "RSA";
        int keyBitSize = 2048;
        String keyAlias = "";
        String keyPass = "";

        do {
            System.out.print("Input an alias to store the key: ");
            keyAlias = scanner.nextLine();/
        } while (keyAlias.isEmpty());

        do {
            System.out.print("Input an password to check the key integrity: ");
            keyPass = scanner.nextLine();
        } while (keyPass.isEmpty());

        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
            SecureRandom secureRandom = new SecureRandom();
            keyPairGenerator.initialize(keyBitSize);

            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            PrivateKey privateKey = keyPair.getPrivate();
            PublicKey publicKey = keyPair.getPublic();

            
            KeyStore.PasswordProtection passwordProtection = new KeyStore.PasswordProtection(keyPass.toCharArray());

            keyStore.setEntry(keyAlias, secretKeyEntry, passwordProtection);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }

    }

}
