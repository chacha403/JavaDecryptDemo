package com.example.rsademo;

import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;

import static java.nio.charset.StandardCharsets.UTF_8;

public class RSACryptoService implements CryptoService {
    private String privateKey;

    public RSACryptoService(String privateKey) {
        this.privateKey = privateKey;
    }

    @Override
    public String encrypt(String text) {
        throw new RuntimeException("Not implemented");
    }

    @Override
    public String decrypt(String text) throws Exception {
        return decrypt(privateKey, text);
    }

    private static String decrypt(String privateKeyString, String content) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        PrivateKey privateKey = getPrivateKey(privateKeyString);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] deBytes = Base64.decodeBase64(content);
        byte[] orgBytes = cipher.doFinal(deBytes);
        return new String(orgBytes, UTF_8);
    }

    private static PrivateKey getPrivateKey(String key) throws Exception {
        byte[] keyBytes = Base64.decodeBase64(key);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(keySpec);
    }
}