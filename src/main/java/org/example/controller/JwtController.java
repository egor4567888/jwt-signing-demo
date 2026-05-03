package org.example.controller;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jwt.*;
import com.nimbusds.jose.jwk.RSAKey;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/token")
public class JwtController {

    @Autowired
    @Qualifier("rsaDecryptionKey")
    private RSAKey rsaJwk;

    @Autowired
    @Qualifier("publicJwsKey")
    private RSAKey publicJwsKey;

    @PostMapping
    public ResponseEntity<String> receiveToken(@RequestBody String jweString) {
        try {

            EncryptedJWT encryptedJWT = EncryptedJWT.parse(jweString);
            RSADecrypter decrypter = new RSADecrypter(rsaJwk.toPrivateKey());
            encryptedJWT.decrypt(decrypter);


            String nestedJws = encryptedJWT.getPayload().toString();
            SignedJWT signedJWT = SignedJWT.parse(nestedJws);
            JWSVerifier verifier = new RSASSAVerifier(publicJwsKey.toRSAPublicKey());

            if (!signedJWT.verify(verifier)) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid JWS signature");
            }


            return ResponseEntity.ok("Valid token received: " + signedJWT.getPayload().toString());

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Error: " + e.getMessage());
        }
    }
}
