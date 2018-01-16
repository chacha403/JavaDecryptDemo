package com.example.rsademo;

public interface CryptoService {
    String encrypt(String text) throws Exception;
    String decrypt(String text) throws Exception;
}
