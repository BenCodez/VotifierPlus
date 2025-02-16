
package com.bencodez.votifierplus.tests;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.InvalidKeyException;

import org.junit.jupiter.api.Test;

import com.vexsoftware.votifier.crypto.RSA;
import com.vexsoftware.votifier.crypto.RSAKeygen;

public class RSATest {

    @Test
    public void encryptDecryptWithValidKeys() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        byte[] data = "Test data".getBytes();
        byte[] encryptedData = RSA.encrypt(data, publicKey);
        byte[] decryptedData = RSA.decrypt(encryptedData, privateKey);

        assertArrayEquals(data, decryptedData);
    }

    @Test
    public void encryptWithNullDataThrowsException() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();

        assertThrows(IllegalArgumentException.class, () -> {
            RSA.encrypt(null, publicKey);
        });
    }

    @Test
    public void decryptWithNullDataThrowsException() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();

        assertThrows(IllegalArgumentException.class, () -> {
            RSA.decrypt(null, privateKey);
        });
    }

    @Test
    public void encryptWithNullKeyThrowsException() throws Exception {
        byte[] data = "Test data".getBytes();

        assertThrows(InvalidKeyException.class, () -> {
            RSA.encrypt(data, null);
        });
    }

    @Test
    public void decryptWithNullKeyThrowsException() throws Exception {
        byte[] data = "Test data".getBytes();

        assertThrows(InvalidKeyException.class, () -> {
            RSA.decrypt(data, null);
        });
    }

    @Test
    public void decryptWithIncorrectKeyThrowsException() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair1 = keyGen.generateKeyPair();
        KeyPair keyPair2 = keyGen.generateKeyPair();
        PublicKey publicKey = keyPair1.getPublic();
        PrivateKey privateKey = keyPair2.getPrivate();

        byte[] data = "Test data".getBytes();
        byte[] encryptedData = RSA.encrypt(data, publicKey);

        assertThrows(Exception.class, () -> {
            RSA.decrypt(encryptedData, privateKey);
        });
    }

    @Test
    public void generateKeyPairWith1024Bits() throws Exception {
        KeyPair keyPair = RSAKeygen.generate(1024);
        assertNotNull(keyPair);
        assertNotNull(keyPair.getPrivate());
        assertNotNull(keyPair.getPublic());
    }

    @Test
    public void generateKeyPairWith2048Bits() throws Exception {
        KeyPair keyPair = RSAKeygen.generate(2048);
        assertNotNull(keyPair);
        assertNotNull(keyPair.getPrivate());
        assertNotNull(keyPair.getPublic());
    }

    @Test
    public void generateKeyPairWithZeroBitsThrowsException() {
        assertThrows(Exception.class, () -> {
            RSAKeygen.generate(0);
        });
    }

    @Test
    public void generateKeyPairWithNegativeBitsThrowsException() {
        assertThrows(Exception.class, () -> {
            RSAKeygen.generate(-1024);
        });
    }
}
