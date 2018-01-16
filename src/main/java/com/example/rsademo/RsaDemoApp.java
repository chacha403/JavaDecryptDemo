package com.example.rsademo;

import com.google.common.base.Joiner;
import com.google.common.collect.ImmutableMap;
import org.apache.catalina.filters.CorsFilter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.web.bind.annotation.CrossOrigin;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Security;
import java.util.List;

import static org.apache.catalina.filters.CorsFilter.*;

@CrossOrigin
@SpringBootApplication
public class RsaDemoApp {
    @Bean
    public FilterRegistrationBean corsFilterRegistration() {
        FilterRegistrationBean registration = new FilterRegistrationBean();
        ImmutableMap<String, String> options = ImmutableMap.<String, String>builder()
                .put(PARAM_CORS_ALLOWED_METHODS, "GET,POST,PUT,DELETE,OPTIONS")
                .put(PARAM_CORS_PREFLIGHT_MAXAGE, "3600")
                .put(PARAM_CORS_REQUEST_DECORATE, "true")
                .put(PARAM_CORS_ALLOWED_HEADERS, "authorization,origin,x-requested-with,access-control-request-headers," +
                        "content-type,access-control-request-method,accept")
                .build();
        registration.setInitParameters(options);
        CorsFilter corsFilter = new CorsFilter();
        registration.setFilter(corsFilter);
        registration.setOrder(0);
        registration.addUrlPatterns("/*");
        registration.setName("corsFilter");
        registration.setEnabled(true);
        return registration;
    }

    @Bean
    public FilterRegistrationBean authorizationFilterRegistration() throws IOException {
        Path p = Paths.get("/Users", "chacha403", "rsa_2048_priv.p8");
        List<String> lines = Files.readAllLines(p);
        String privKey = Joiner.on("").join(lines);
        FilterRegistrationBean registration = new FilterRegistrationBean();
        SecKeyInfo secKeyInfo = new SecKeyInfo();
        secKeyInfo.setAlgorithm("rsa");
        secKeyInfo.setPrivateKey(privKey);
        DecryptFilter decryptFilter = new DecryptFilter(secKeyInfo);
        registration.setFilter(decryptFilter);
        registration.setOrder(1);
        registration.addUrlPatterns("/*");
        registration.setName("decryptFilter");
        return registration;
    }

    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());
        SpringApplication.run(RsaDemoApp.class, args);
    }
}
