package social.bubble.thebubblesocial.service;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Service;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Date;

@Service
public class AppleTokenService {

    @Value("${apple.auth.keyId}")
    private String keyId;

    @Value("${apple.auth.teamId}")
    private String teamId;

    @Value("${spring.security.oauth2.client.registration.apple.client-id}")
    private String clientId;

    private PrivateKey getPrivateKey() throws Exception {
        Logger logger = LoggerFactory.getLogger(AppleTokenService.class);
        Resource resource = new ClassPathResource("AuthKey_4D2D59QHU3.p8");
        InputStream inputStream = resource.getInputStream();

        if (inputStream == null) {
            throw new FileNotFoundException("Key file not found in classpath: " + resource.getFilename());
        }

        String key = new String(inputStream.readAllBytes(), StandardCharsets.UTF_8);
        key = key.replaceAll("-----END PRIVATE KEY-----", "")
                .replaceAll("-----BEGIN PRIVATE KEY-----", "")
                .replaceAll("\\s", "");

        try {
            byte[] keyBytes = Base64.getDecoder().decode(key);
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("EC");
            return kf.generatePrivate(spec);
        } catch (NoSuchAlgorithmException e) {
            throw new TokenServiceException("No such algorithm for key factory", e);
        } catch (InvalidKeySpecException e) {
            throw new TokenServiceException("Invalid key specification", e);
        } finally {
            inputStream.close();
        }

    }

    public String generateToken() throws TokenServiceException {
        try {
            long nowMillis = System.currentTimeMillis();
            Date now = new Date(nowMillis);
            Date expiryDate = new Date(nowMillis + 3600000); // 1 hour validity

            return Jwts.builder()
                    .setHeaderParam("kid", keyId)
                    .setIssuer(teamId)
                    .setIssuedAt(now)
                    .setExpiration(expiryDate)
                    .setAudience("https://appleid.apple.com")
                    .setSubject(clientId)
                    .signWith(getPrivateKey(), SignatureAlgorithm.ES256)
                    .compact();
        } catch (Exception e) {
            throw new TokenServiceException("Error generating token", e);
        }
    }

    public static class TokenServiceException extends Exception {
        public TokenServiceException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
