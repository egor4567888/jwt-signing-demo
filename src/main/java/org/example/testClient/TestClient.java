package org.example.testClient;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jwt.*;

import javax.net.ssl.*;
import java.net.URI;
import java.nio.file.*;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.interfaces.*;
import java.security.spec.*;
import java.util.*;

import java.net.http.*;

public class TestClient {

    public static void main(String[] args) throws Exception {
        RSAPrivateKey senderPrivateKey = loadPrivateKey("private.pem");

        RSAPublicKey serverPublicKey = loadPublicKey("server-public.pem");

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject("alice")
                .issuer("client-app")
                .expirationTime(new Date(new Date().getTime() + 60_000))
                .claim("role", "user")
                .build();

        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader(JWSAlgorithm.RS256),
                claims
        );

        JWSSigner signer = new RSASSASigner(senderPrivateKey);
        signedJWT.sign(signer);

        JWEObject jwe = new JWEObject(
                new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM).contentType("JWT").build(),
                new Payload(signedJWT)
        );

        jwe.encrypt(new RSAEncrypter(serverPublicKey));

        String jweToken = jwe.serialize();

        sendToServer(jweToken);
    }

    static RSAPublicKey loadPublicKey(String filePath) throws Exception {
        String key = Files.readString(Path.of(filePath))
                .replaceAll("-----\\w+ PUBLIC KEY-----", "")
                .replaceAll("\\s", "");
        byte[] decoded = Base64.getDecoder().decode(key);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
        return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(spec);
    }

    static RSAPrivateKey loadPrivateKey(String filePath) throws Exception {
        String key = Files.readString(Path.of(filePath))
                .replaceAll("-----\\w+ PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
        byte[] decoded = Base64.getDecoder().decode(key);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decoded);
        return (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(spec);
    }

    static void sendToServer(String jweToken) throws Exception {

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, new TrustManager[]{new X509TrustManager() {
            public void checkClientTrusted(X509Certificate[] x, String s) {}
            public void checkServerTrusted(X509Certificate[] x, String s) {}
            public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
        }}, new SecureRandom());

        HttpClient client = HttpClient.newBuilder()
                .sslContext(sslContext)
                .build();

        HttpRequest request = HttpRequest.newBuilder()
                .uri(new URI("https://localhost:8443/api/token"))
                .header("Content-Type", "text/plain")
                .POST(HttpRequest.BodyPublishers.ofString(jweToken))
                .build();

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        System.out.println("Response code: " + response.statusCode());
        System.out.println("Response body: " + response.body());
    }
}
