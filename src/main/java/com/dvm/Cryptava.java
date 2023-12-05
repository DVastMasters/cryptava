package com.dvm;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
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

    /**
     * THE STORE TO SAVE THE KEYS AND CERTIFICATES
     */
    private static KeyStore keyStore;

    public static void main(String[] args) {
        do {
            System.out.println(
                    "--- Options ---" + lineSeparator +
                            "1. Load a key storage." + lineSeparator +
                            "2. Generate a symmetric key." + lineSeparator +
                            "3. Generate a key-pair (asymmetric)" + lineSeparator +
                            "0. Quit.");

            System.out.print("Choose a option: ");
            option = Integer.parseInt(scanner.nextLine());

            switch (option) {
                case 1:
                    loadKeyStore();
                    break;
                case 2:
                    // generateKey();
                    break;
                case 3:
                    // generateKeyPair();
            }

        } while (option != 0);

    }

    public static void loadKeyStore() {
        String storeFileName;
        File storeFile;
        String storePassword = "";

        try {
            keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        } catch (KeyStoreException e) {
            System.out.println("Cannot get a keyStore instance.");
            e.printStackTrace();
            return;
        }

        do {
            System.out.print("Input a valid keyStore filename: ");
            storeFileName = scanner.nextLine();

            storeFile = new File(storeFileName);
        } while (!storeFile.isFile());

        while (true) {
            System.out.print("Input the keyStore password: ");
            storePassword = scanner.nextLine();

            try (InputStream keyStoreData = new FileInputStream(storeFile)) {
                keyStore.load(keyStoreData, storePassword.toCharArray());
                break;
            } catch (IOException e) {
                if (e.getCause() instanceof UnrecoverableKeyException) {
                    System.out.println("The password is invalid.");
                } else {
                    System.out.println("Cannot open the storeKey file.");
                }
                e.printStackTrace();
            } catch (NoSuchAlgorithmException e) {
                System.out.println("Cannot load the algorithm to verify the store.");
                e.printStackTrace();
            } catch (CertificateException e) {
                System.out.println("Cannot load one or more store certificates.");
                e.printStackTrace();
            }
        }

    }

}
