package com.dvm;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
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

    private static String asymmetricAlgorithm = "RSA";
    private static int asymmetricAlgorithmKeyBitSize = 2048;

    private static String symmetricAlgorithm = "AES";
    private static int symmetricAlgorithmKeyBitSize = 256;
    private static String cipherMode = "CBC";

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
                    // encryptFile();
                    break;
                case 3:
                    // decryptFile();
            }

        } while (option != 0);
    }

    public static void generateKeyPair() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(asymmetricAlgorithm);
            keyPairGenerator.initialize(asymmetricAlgorithmKeyBitSize);

            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            PrivateKey privateKey = keyPair.getPrivate();
            PublicKey publicKey = keyPair.getPublic();

            try (FileOutputStream fOutput = new FileOutputStream("yourPublic.key")) {
                // Encode the key in a standard format (X.509)
                fOutput.write(publicKey.getEncoded());
            } catch (FileNotFoundException e) {
                e.printStackTrace();
                System.out.println("Cannot is possible to create the yourPublic.key file.");
            } catch (IOException e) {
                e.printStackTrace();
            }

            try (FileOutputStream fOutput = new FileOutputStream("yourPrivate.key")) {
                // Encode the key in a standard format (X.509)
                fOutput.write(privateKey.getEncoded());
            } catch (FileNotFoundException e) {
                e.printStackTrace();
                System.out.println("Cannot is possible to create the yourPrivate.key file.");
            } catch (IOException e) {
                e.printStackTrace();
            }
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        System.out.println(
                "The public key is stored in yourPublic.key file and the private key is stored in yourPrivate.key file.");
    }
}
