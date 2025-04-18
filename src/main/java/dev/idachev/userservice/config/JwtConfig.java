package dev.idachev.userservice.config;

import dev.idachev.userservice.model.User;
import dev.idachev.userservice.security.UserPrincipal;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;
import java.util.UUID;
import java.util.function.Function;

@Slf4j
@Component
public class JwtConfig {

    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.expiration}")
    private Long expiration;

    private Key signingKey;

    @PostConstruct
    public void init() {
        try {
            byte[] keyBytes = secret.getBytes(StandardCharsets.UTF_8);
            int keyBitSize = keyBytes.length * 8;

            if (keyBitSize < 384) {
                log.warn("JWT secret too small: {} bits < 384 bits - generating secure key", keyBitSize);
                this.signingKey = Keys.secretKeyFor(SignatureAlgorithm.HS384);
            } else {
                this.signingKey = Keys.hmacShaKeyFor(keyBytes);
                log.info("JWT key initialized: {} bits", keyBitSize);
            }
        } catch (Exception e) {
            log.error("JWT key init error: {}", e.getMessage());
            this.signingKey = Keys.secretKeyFor(SignatureAlgorithm.HS384);
        }
    }

    public String generateToken(UserDetails userDetails) {
        long now = System.currentTimeMillis();
        Date issuedAt = new Date(now);
        Date expiry = new Date(now + expiration);
        
        if (userDetails instanceof UserPrincipal userPrincipal) {
            User user = userPrincipal.user();

            return Jwts.builder()
                .setSubject(userDetails.getUsername())
                .claim("userId", user.getId().toString())
                .claim("role", user.getRole().toString())
                .claim("email", user.getEmail())
                .claim("banned", user.isBanned())
                .setIssuedAt(issuedAt)
                .setExpiration(expiry)
                .setId(UUID.randomUUID().toString())
                .signWith(signingKey, SignatureAlgorithm.HS384)
                .compact();
        }

        return Jwts.builder()
            .setSubject(userDetails.getUsername())
            .setIssuedAt(issuedAt)
            .setExpiration(expiry)
            .setId(UUID.randomUUID().toString())
            .signWith(signingKey, SignatureAlgorithm.HS384)
            .compact();
    }

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public UUID extractUserId(String token) {
        try {
            final Claims claims = extractAllClaims(token);
            String userIdStr = claims.get("userId", String.class);
            if (userIdStr == null) {
                log.warn("User ID claim (userId) is missing from token");
                throw new JwtException("Missing required claim: userId"); 
            }
            return UUID.fromString(userIdStr);
        } catch (IllegalArgumentException e) {
            log.warn("Invalid User ID format in token claim: {}", e.getMessage());
            throw new JwtException("Invalid format for claim: userId", e);
        } catch (JwtException e) {
             throw e;
        } catch (Exception e) {
             log.error("Unexpected error extracting userId claim: {}", e.getMessage(), e);
             throw new JwtException("Failed to extract userId claim due to unexpected error", e);
        }
    }

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        try {
            return Jwts.parserBuilder()
                .setSigningKey(signingKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
        } catch (ExpiredJwtException e) {
            log.debug("JWT token expired: {}", e.getMessage());
            throw e;
        } catch (SignatureException | MalformedJwtException e) {
            log.warn("Invalid JWT signature: {}", e.getMessage());
            throw e;
        } catch (UnsupportedJwtException e) {
            log.warn("JWT token is unsupported: {}", e.getMessage());
            throw e;
        } catch (IllegalArgumentException e) {
            log.warn("JWT claims string is empty: {}", e.getMessage());
            throw e;
        } catch (Exception e) {
            log.error("Error parsing JWT token: {}", e.getMessage());
            throw e;
        }
    }

    public boolean isTokenExpired(String token) {
        try {
            return extractExpiration(token).before(new Date());
        } catch (ExpiredJwtException e) {
            return true;
        }
    }

    public boolean validateToken(String token, UserDetails userDetails) {
        if (token == null || token.isBlank()) {
            return false;
        }
        
        try {
            final String username = extractUsername(token);
            return username != null && 
                   username.equals(userDetails.getUsername()) && 
                   !isTokenExpired(token) && 
                   userDetails.isEnabled();
        } catch (ExpiredJwtException e) {
            return false;
        } catch (Exception e) {
            log.warn("Token validation failed: {}", e.getMessage());
            return false;
        }
    }
} 
