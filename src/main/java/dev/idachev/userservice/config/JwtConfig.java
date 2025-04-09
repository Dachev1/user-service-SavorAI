package dev.idachev.userservice.config;

import dev.idachev.userservice.model.User;
import dev.idachev.userservice.security.UserPrincipal;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
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
import java.util.Base64;


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
            
            // For HS384, need at least 384 bits
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

    /**
     * Generates an access token for the provided user details
     *
     * @param userDetails User details from Spring Security
     * @return JWT token string
     */
    public String generateToken(UserDetails userDetails) {
        if (userDetails instanceof UserPrincipal) {
            User user = ((UserPrincipal) userDetails).user();

            return Jwts.builder().setSubject(userDetails.getUsername()).claim("userId", user.getId().toString()).claim("role", user.getRole().toString()).claim("email", user.getEmail()).claim("banned", user.isBanned()).setIssuedAt(new Date()).setExpiration(new Date(System.currentTimeMillis() + expiration)).signWith(signingKey, io.jsonwebtoken.SignatureAlgorithm.HS384).compact();
        }

        // For non-UserPrincipal users (should not happen in normal flow)
        return Jwts.builder().setSubject(userDetails.getUsername()).setIssuedAt(new Date()).setExpiration(new Date(System.currentTimeMillis() + expiration)).signWith(signingKey, io.jsonwebtoken.SignatureAlgorithm.HS384).compact();
    }

    /**
     * Extracts the username from a token
     *
     * @param token JWT token
     * @return Username string
     */
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    /**
     * Extracts the user ID from a token
     *
     * @param token JWT token
     * @return User ID as UUID
     */
    public UUID extractUserId(String token) {
        final Claims claims = extractAllClaims(token);
        String userIdStr = claims.get("userId", String.class);
        if (userIdStr == null) {
            throw new JwtException("User ID claim is missing from the token");
        }
        try {
            return UUID.fromString(userIdStr);
        } catch (IllegalArgumentException e) {
            throw new JwtException("Invalid User ID format in the token", e);
        }
    }

    /**
     * Extracts the expiration date from a token
     *
     * @param token JWT token
     * @return Expiration date
     */
    public Date extractExpiration(String token) {

        return extractClaim(token, Claims::getExpiration);
    }

    /**
     * Extracts a specific claim from a token using the provided claims resolver function
     *
     * @param token          JWT token
     * @param claimsResolver Function to extract a specific claim
     * @return The extracted claim value
     */
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {

        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    /**
     * Extracts all claims from a token
     *
     * @param token JWT token
     * @return All claims
     * @throws io.jsonwebtoken.JwtException if the token is invalid
     */
    private Claims extractAllClaims(String token) {

        try {

            return Jwts.parserBuilder().setSigningKey(signingKey).build().parseClaimsJws(token).getBody();

        } catch (ExpiredJwtException e) {

            log.warn("JWT token expired: {}", e.getMessage());
            throw e;
        } catch (MalformedJwtException e) {

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

    /**
     * Checks if a token is expired
     *
     * @param token JWT token
     * @return true if expired, false otherwise
     */
    public Boolean isTokenExpired(String token) {

        try {

            return extractExpiration(token).before(new Date());
        } catch (ExpiredJwtException e) {

            return true;
        }
    }

    /**
     * Validates a token for the given user details
     *
     * @param token       JWT token
     * @param userDetails User details to validate against
     * @return true if valid, false otherwise
     */
    public Boolean validateToken(String token, UserDetails userDetails) {

        try {

            final String username = extractUsername(token);
            return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
        } catch (Exception e) {

            log.warn("Token validation failed: {}", e.getMessage());
            return false;
        }
    }
} 
