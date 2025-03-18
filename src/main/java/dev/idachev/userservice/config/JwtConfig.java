package dev.idachev.userservice.config;

import dev.idachev.userservice.model.User;
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
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;

/**
 * Configuration for JWT token generation, validation, and parsing.
 * Provides methods for creating access and refresh tokens, as well as
 * validating and parsing token information.
 */
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
        // Use the HMAC-SHA384 algorithm to sign tokens (matching the recipe-service)
        byte[] secretBytes = secret.getBytes(StandardCharsets.UTF_8);
        this.signingKey = Keys.hmacShaKeyFor(secretBytes);

        log.info("JWT signing key initialized successfully with algorithm: {}", "HS384");
    }

    /**
     * Generates an access token for the provided user details
     *
     * @param userDetails User details from Spring Security
     * @return JWT token string
     */
    public String generateToken(UserDetails userDetails) {

        return generateToken(new HashMap<>(), userDetails);
    }

    /**
     * Generates an access token with additional claims
     *
     * @param extraClaims Additional claims to include in the token
     * @param userDetails User details from Spring Security
     * @return JWT token string
     */
    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {

        return buildToken(extraClaims, userDetails, expiration);
    }

    /**
     * Common method to build a token with specific expiration
     *
     * @param extraClaims Additional claims to include in the token
     * @param userDetails User details from Spring Security
     * @param expiration  Expiration time in milliseconds
     * @return JWT token string
     */
    private String buildToken(Map<String, Object> extraClaims, UserDetails userDetails, long expiration) {

        Map<String, Object> claims = new HashMap<>(extraClaims);
        claims.put("authorities", userDetails.getAuthorities());

        // Add user-specific claims
        if (userDetails instanceof User user) {
            claims.put("userId", user.getId().toString());
            claims.put("email", user.getEmail());
        }

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .setId(UUID.randomUUID().toString())
                .signWith(signingKey, io.jsonwebtoken.SignatureAlgorithm.HS384) // Explicitly use HS384
                .compact();
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

            return Jwts.parserBuilder()
                    .setSigningKey(signingKey)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

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
