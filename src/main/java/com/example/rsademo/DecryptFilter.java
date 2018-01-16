package com.example.rsademo;

import com.google.common.base.Charsets;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.IOUtils;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

@Slf4j
public class DecryptFilter implements Filter {

    private SecKeyInfo secKeyInfo;

    public DecryptFilter(SecKeyInfo secKeyInfo) {
        this.secKeyInfo = secKeyInfo;
    }

    @Override
    public void init(FilterConfig filterConfig) {
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;

        if (Objects.equals(HttpMethod.OPTIONS.name(), request.getMethod())) {
            filterChain.doFilter(request, response);
            return;
        }
        if (secKeyInfo != null) {
            byte[] requestBytes = IOUtils.toByteArray(request.getInputStream());
            String plainBody = new String(requestBytes, Charsets.UTF_8);
            String[] aesKeyAndCipher = plainBody.split(":::");

            String encryptedAES256Key = aesKeyAndCipher[0];
            String cipherText = aesKeyAndCipher[1];
            CryptoService rsaCryptoService;
            if (secKeyInfo.getAlgorithm().equalsIgnoreCase("rsa")) {
                rsaCryptoService = new RSACryptoService(secKeyInfo.getPrivateKey());
                try {
                    String aesDecrypted = rsaCryptoService.decrypt(encryptedAES256Key);
                    String[] aesKeyAndIV = aesDecrypted.split(":::");
                    byte[] aes256Key = Hex.decodeHex(aesKeyAndIV[0].toCharArray());
                    byte[] iv = Hex.decodeHex(aesKeyAndIV[1].toCharArray());
                    String plainText = decrypt(aes256Key, iv, cipherText);
                    filterChain.doFilter(new CustomHttpServletRequestWrapper(request, plainText), response);
                } catch (Exception e) {
                    log.error("failed to read from request input stream", e);
                }
            } else {
                log.error("Invalid security key algorithm");
            }
        } else {
            filterChain.doFilter(request, response);
        }
    }

    @Override
    public void destroy() {

    }


    private String decrypt(byte[] aesKey, byte[] iv, String encryptedText) throws Exception {
        SecretKey secretKeySpec = new SecretKeySpec(aesKey, "AES");
        byte[] encryptedBytes = Base64.decodeBase64(encryptedText);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        Cipher cipherDecrypt = Cipher.getInstance("AES/CBC/PKCS7Padding");
        cipherDecrypt.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
        byte[] decrypted = cipherDecrypt.doFinal(encryptedBytes);
        return new String(decrypted, StandardCharsets.UTF_8);
    }


    private static class CustomHttpServletRequestWrapper extends HttpServletRequestWrapper {
        private String plainText = null;

        public CustomHttpServletRequestWrapper(HttpServletRequest request, String plainText) {
            super(request);
            try {
                this.plainText = plainText;
            } catch (Exception e) {
                log.error("failed to read from request input stream", e);
            }
        }

        @Override
        public String getContentType() {
            return MediaType.APPLICATION_JSON_UTF8_VALUE;
        }

        @Override
        public ServletInputStream getInputStream() {
            final ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(plainText.getBytes(Charsets.UTF_8));
            return new ServletInputStream() {
                @Override
                public boolean isFinished() {
                    return byteArrayInputStream.available() == 0;
                }

                @Override
                public boolean isReady() {
                    return true;
                }

                @Override
                public void setReadListener(ReadListener listener) {

                }

                public int read() {
                    return byteArrayInputStream.read();
                }
            };
        }

        @Override
        public BufferedReader getReader() {
            return new BufferedReader(new InputStreamReader(this.getInputStream()));
        }
    }
}
