package dev.idachev.recipeservice.config;

import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.Key;

/**
 * Creates and manages the JWT signing key used for token validation.
 * This ensures compatibility with the auth-service JWT implementation.
 */
@Component
@Slf4j
public class JwtKeyConfig {

    @Value("${jwt.secret}")
    private String secret;

    @Getter
    private Key signingKey;

    @PostConstruct
    public void init() {
        try {
            byte[] secretBytes = secret.getBytes(StandardCharsets.UTF_8);
            
            // Ensure key is long enough for HS384 (needs at least 48 bytes)
            if (secretBytes.length < 48) {
                byte[] paddedKey = new byte[48];
                System.arraycopy(secretBytes, 0, paddedKey, 0, secretBytes.length);
                secretBytes = paddedKey;
            }
            
            this.signingKey = Keys.hmacShaKeyFor(secretBytes);
            log.info("JWT signing key initialized successfully");
        } catch (Exception e) {
            log.error("Failed to initialize JWT signing key: {}", e.getMessage());
            throw new RuntimeException("JWT signing key initialization failed", e);
        }
    }
} 