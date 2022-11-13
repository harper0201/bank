import java.io.*;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.Cipher;

public class generateRSAKey {
    public static final String ALGORITHM = "RSA";
    public static final String PRIVATE_KEY_FILE = "Prt";	//values changed fr each key
    public static final String PUBLIC_KEY_FILE = "Put";


//    public static void main(String[] args) throws FileNotFoundException {
//        try {
//            final String originalText = "Text to be encrypted ";
//            ObjectInputStream inputStream = null;
//
//            generateKey();
//            // Encrypt the string using the public key
//            inputStream = new ObjectInputStream(new FileInputStream(PUBLIC_KEY_FILE));
//            final PublicKey publicKey = (PublicKey) inputStream.readObject();
//            final byte[] cipherText = encrypt(originalText, publicKey);
//
//            // Decrypt the cipher text using the private key.
//            inputStream = new ObjectInputStream(new FileInputStream(PRIVATE_KEY_FILE));
//            final PrivateKey privateKey = (PrivateKey) inputStream.readObject();
//            final String plainText = decrypt(cipherText, privateKey);
//
//            // Printing the Original, Encrypted and Decrypted Text
//            System.out.println("Original: " + originalText);
//            System.out.println("Encrypted: " +cipherText.toString());
//            System.out.println("Decrypted: " + plainText);
//
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
//
//    }

    public  boolean areKeysPresent() {
        File privateKey = new File(PRIVATE_KEY_FILE);
        File publicKey = new File(PUBLIC_KEY_FILE);

        if (privateKey.exists() && publicKey.exists()) {
            return true;
        }
        return false;
    }

    public PublicKey getPublicKey() throws Exception {
        ObjectInputStream inputStream = null;
        inputStream = new ObjectInputStream(new FileInputStream(PUBLIC_KEY_FILE));
        final PublicKey publicKey;
        try {
            publicKey = (PublicKey) inputStream.readObject();
        } catch (ClassNotFoundException e) {
            throw new RuntimeException(e);
        }
        return publicKey;
    }

    public PrivateKey getPrivateKey() throws Exception {
        ObjectInputStream inputStream = null;
        inputStream = new ObjectInputStream(new FileInputStream(PRIVATE_KEY_FILE));
        final PrivateKey privateKey = (PrivateKey) inputStream.readObject();
        return privateKey;
    }
    public void  generateKey() {
        try {
            final KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM);
            keyGen.initialize(1024);
            KeyPair key = keyGen.generateKeyPair();

            File privateKeyFile = new File(PRIVATE_KEY_FILE);
            File publicKeyFile = new File(PUBLIC_KEY_FILE);

            // Create files to store public and private key
            if (privateKeyFile.getParentFile() != null) {
                privateKeyFile.getParentFile().mkdirs();
            }
            privateKeyFile.createNewFile();

            if (publicKeyFile.getParentFile() != null) {
                publicKeyFile.getParentFile().mkdirs();
            }
            publicKeyFile.createNewFile();

            // Saving the Public key in a file
            ObjectOutputStream publicKeyOS = new ObjectOutputStream(
                    new FileOutputStream(publicKeyFile));
            publicKeyOS.writeObject(key.getPublic());
            publicKeyOS.close();

            // Saving the Private key in a file
            ObjectOutputStream privateKeyOS = new ObjectOutputStream(
                    new FileOutputStream(privateKeyFile));
            privateKeyOS.writeObject(key.getPrivate());
            privateKeyOS.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public byte[] encrypt(String text, PublicKey key) {
        byte[] cipherText = null;
        try {
            // get an RSA cipher object and print the provider
            final Cipher cipher = Cipher.getInstance(ALGORITHM);
            // encrypt the plain text using the public key
            cipher.init(Cipher.ENCRYPT_MODE, key);
            cipherText = cipher.doFinal(text.getBytes());
        } catch (Exception e) {
            e.printStackTrace();
        }
        return cipherText;
    }

    public String decrypt(byte[] text, PrivateKey key) {
        byte[] dectyptedText = null;
        try {
            // get an RSA cipher object and print the provider
            final Cipher cipher = Cipher.getInstance(ALGORITHM);

            // decrypt the text using the private key
            cipher.init(Cipher.DECRYPT_MODE, key);
            dectyptedText = cipher.doFinal(text);

        } catch (Exception e) {
            e.printStackTrace();
        }

        return new String(dectyptedText);
    }
}
