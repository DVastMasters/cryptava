package com.dvm;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

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
                    encryptFile();
                    break;
                case 3:
                    decryptFile();
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

    public static void encryptFile() {
        System.out.println(
                "The encryption process will be: " + lineSeparator +
                        "1. Generate a new temporary symmetric key with 256 bits to use the AES algorithm."
                        + lineSeparator +
                        "2. Encrypt the file with the symmetric key." + lineSeparator +
                        "3. Encrypt the symmetric key with the public key from the message receiver." + lineSeparator +
                        "So, you'll send the symmetric key encrypted (tempSymmetricKey.key) and the encrypted file (encrypted.data) to the receiver.");
        /*
         * 1. Generate a new temporary symmetric key with 256 bits to use the AES
         * algorithm.
         */

        SecretKey secretKey = null;
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(symmetricAlgorithm);
            SecureRandom secureRandom = new SecureRandom(); // Ensure the randomness
            keyGenerator.init(symmetricAlgorithmKeyBitSize, secureRandom);
            secretKey = keyGenerator.generateKey();

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        /*
         * 2. Encrypt the file with the symmetric key.
         */
        String fileNameToEncrypt;
        File fileToEncrypt;
        do {
            System.out.print("Input the filename to encrypt: ");
            fileNameToEncrypt = scanner.nextLine();
            fileToEncrypt = new File(fileNameToEncrypt);
        } while (fileNameToEncrypt.isEmpty() || !fileToEncrypt.isFile());

        Cipher encryptCipher;
        try {
            encryptCipher = Cipher.getInstance(symmetricAlgorithm);
            encryptCipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] fileToEncryptBytes;
            try (FileInputStream iStream = new FileInputStream(fileToEncrypt)) {
                fileToEncryptBytes = iStream.readAllBytes();
            }

            byte[] fileToEncryptEncrypted = encryptCipher.doFinal(fileToEncryptBytes);

            try (FileOutputStream oStream = new FileOutputStream("encrypted.data")) {
                oStream.write(fileToEncryptEncrypted);
            }
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        }

        /*
         * 3. Encrypt the symmetric key with the public key from the message receiver.
         */
        String publicKeyDestFilename;
        File publicKeyDestFile;
        byte[] publicKeyDestBytes = null;
        do {
            System.out.print("Input the public key filename (encoded in the X.509 format): ");
            publicKeyDestFilename = scanner.nextLine();
            publicKeyDestFile = new File(publicKeyDestFilename);
            try {
                publicKeyDestBytes = Files.readAllBytes(publicKeyDestFile.toPath());
            } catch (IOException e) {
                System.out.println("The file cannot be read.");
                e.printStackTrace();
            }
        } while (!publicKeyDestFile.isFile());

        EncodedKeySpec publicKeyDestSpec;
        KeyFactory keyFactory;
        PublicKey publicKeyDest = null;
        try {
            keyFactory = KeyFactory.getInstance(asymmetricAlgorithm);
            publicKeyDestSpec = new X509EncodedKeySpec(publicKeyDestBytes);
            publicKeyDest = keyFactory.generatePublic(publicKeyDestSpec);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return;
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
            System.out.println("Invalid public key!");
        }

        // Encode the secret key in the X.509 standard.
        byte[] secretKeyBytes = secretKey.getEncoded();
        byte[] secretKeyBytesEncrypted = null;
        try {
            encryptCipher = Cipher.getInstance(asymmetricAlgorithm);
            encryptCipher.init(Cipher.ENCRYPT_MODE, publicKeyDest);
            secretKeyBytesEncrypted = encryptCipher.doFinal(secretKeyBytes);
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }

        // Save the encrypted symmetric key
        try (FileOutputStream fOutput = new FileOutputStream("tempSymmetricKey.key")) {
            fOutput.write(secretKeyBytesEncrypted);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

    public static void decryptFile() {
        System.out.println(
                "The decryption process will be: " + lineSeparator +
                        "1. Decrypt the temporary symmetric key using your private key." + lineSeparator +
                        "2. Decrypt the file with the symmetric key.");
        /*
         * 1. Decrypt the temporary symmetric key using your private key.
         */

        // READING THE PRIVATE KEY

        String privateKeyFilename;
        File privateKeyFile;
        byte[] privateKeyBytes = null;
        do {
            System.out.print("Input the filename with your private key: ");
            privateKeyFilename = scanner.nextLine();
            privateKeyFile = new File(privateKeyFilename);
            try {
                privateKeyBytes = Files.readAllBytes(privateKeyFile.toPath());
            } catch (IOException e) {
                e.printStackTrace();
            }
        } while (!privateKeyFile.isFile());

        EncodedKeySpec privateKeySpec;
        KeyFactory keyFactory;
        PrivateKey privateKey = null;
        try {
            keyFactory = KeyFactory.getInstance(asymmetricAlgorithm);
            privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
            privateKey = keyFactory.generatePrivate(privateKeySpec);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }

        // DECRYPTING THE SYMMETRIC KEY

        String symmetricKeyFilename;
        File symmetricKeyFile;
        do {
            System.out.print("Input the filename with the symmetric key: ");
            symmetricKeyFilename = scanner.nextLine();
            symmetricKeyFile = new File(symmetricKeyFilename);
        } while (!symmetricKeyFile.isFile());

        Cipher encryptCipher;
        SecretKey symmetricKey = null;
        try {
            encryptCipher = Cipher.getInstance(asymmetricAlgorithm);
            encryptCipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] symmetricKeyBytes;
            try (FileInputStream iStream = new FileInputStream(symmetricKeyFile)) {
                symmetricKeyBytes = iStream.readAllBytes();
            }

            byte[] symmetricKeyDecryptedBytes = encryptCipher.doFinal(symmetricKeyBytes);
            symmetricKey = new SecretKeySpec(symmetricKeyDecryptedBytes, 0, symmetricKeyDecryptedBytes.length, "AES");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        }

        /*
         * 3. Decrypt the file with the symmetric key
         */
        String encryptedFilename;
        File encryptedFile;
        byte[] encryptedFileBytes = null;
        do {
            System.out.println("Input the filename of the encrypted data: ");

            encryptedFilename = scanner.nextLine();
            encryptedFile = new File(encryptedFilename);
            try {
                encryptedFileBytes = Files.readAllBytes(encryptedFile.toPath());
            } catch (IOException e) {
                System.out.println("The file cannot be read.");
                e.printStackTrace();
            }
        } while (!encryptedFile.isFile());

        byte[] decryptedFile = null;
        try {
            encryptCipher = Cipher.getInstance(symmetricAlgorithm);
            encryptCipher.init(Cipher.DECRYPT_MODE, symmetricKey);
            decryptedFile = encryptCipher.doFinal(encryptedFileBytes);
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }

        // Save the encrypted symmetric key
        try (FileOutputStream fOutput = new FileOutputStream("decrypted.data")) {
            fOutput.write(decryptedFile);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

}
