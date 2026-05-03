package org.example.config;

import com.nimbusds.jose.jwk.RSAKey;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Configuration
public class KeyConfig {
    @Bean
    public RSAKey rsaDecryptionKey() throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(new FileInputStream("src/main/resources/keystore.p12"), "password".toCharArray());

        Key key = ks.getKey("jwtserver", "password".toCharArray());
        Certificate cert = ks.getCertificate("jwtserver");

        return new RSAKey.Builder((RSAPublicKey) cert.getPublicKey())
                .privateKey((PrivateKey) key)
                .keyID("jwtserver")
                .build();
    }

    @Bean
    public RSAKey publicJwsKey() throws Exception {
        String pem = Files.readString(Path.of("src/main/resources/public.pem"));
        String clean = pem.replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");
        byte[] decoded = Base64.getDecoder().decode(clean);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPublicKey publicKey = (RSAPublicKey) kf.generatePublic(new X509EncodedKeySpec(decoded));

        return new RSAKey.Builder(publicKey).keyID("sender-key").build();
    }
}