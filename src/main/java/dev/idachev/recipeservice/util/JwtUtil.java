package dev.idachev.recipeservice.util;

import dev.idachev.recipeservice.config.JwtKeyConfig;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;
import java.security.Key;

/**
 * Utility class for JWT token operations.
 * Handles token validation and data extraction.
 */
@Component
@Slf4j
public class JwtUtil {

    private final Key signingKey;

    public JwtUtil(JwtKeyConfig jwtKeyConfig) {
        this.signingKey = jwtKeyConfig.getSigningKey();
        log.info("JWT validation utility initialized");
    }

    /**
     * Helper method to log token details for debugging
     */
    private void logTokenDetails(String token) {
        try {
            String[] chunks = token.split("\\.");
            if (chunks.length >= 2) {
                Base64.Decoder decoder = Base64.getUrlDecoder();
                String header = new String(decoder.decode(chunks[0]));
                log.debug("JWT token algorithm from header: {}", header.contains("HS384") ? "HS384" : "UNKNOWN");
            }
        } catch (Exception e) {
            log.warn("Error examining token: {}", e.getMessage());
        }
    }

    /**
     * Extract user ID from JWT token.
     */
    public UUID extractUserId(String token) {
        Claims claims = extractAllClaims(token);
        
        // Try to extract userId from common claim keys
        for (String key : List.of("userId", "user_id", "id", "sub")) {
            Object claim = claims.get(key);
            if (claim != null) {
                String idStr = claim.toString();
                try {
                    return UUID.fromString(idStr);
                } catch (IllegalArgumentException e) {
                    if (idStr.matches("\\d+")) {
                        return UUID.nameUUIDFromBytes(idStr.getBytes());
                    }
                }
            }
        }
        
        // Last resort: use subject
        String subject = claims.getSubject();
        if (subject != null) {
            return UUID.nameUUIDFromBytes(subject.getBytes());
        }
        
        throw new IllegalArgumentException("Token does not contain valid user identification");
    }
    
    /**
     * Extract username from JWT token.
     */
    public String extractUsername(String token) {
        Claims claims = extractAllClaims(token);
        
        // Try username claim first, then fall back to subject
        String username = null;
        
        for (String key : List.of("username", "name", "preferred_username", "email")) {
            if (claims.get(key) != null) {
                username = claims.get(key).toString();
                break;
            }
        }
        
        // Fall back to subject
        if (username == null) {
            username = claims.getSubject();
        }
        
        return username != null ? username : "unknown";
    }
    
    /**
     * Extract authorities/roles from JWT token.
     */
    @SuppressWarnings("unchecked")
    public List<GrantedAuthority> extractAuthorities(String token) {
        Claims claims = extractAllClaims(token);
        List<GrantedAuthority> authorities = new ArrayList<>();
        
        try {
            // Format 1: "authorities": [{"authority": "ROLE_USER"}, ...]
            if (claims.get("authorities") instanceof List) {
                List<LinkedHashMap<String, String>> authsList = (List<LinkedHashMap<String, String>>) claims.get("authorities");
                
                if (authsList != null && !authsList.isEmpty()) {
                    authorities = authsList.stream()
                        .filter(map -> map.containsKey("authority"))
                        .map(map -> new SimpleGrantedAuthority(map.get("authority")))
                        .collect(Collectors.toList());
                }
            }
            
            // Format 2: "roles": ["USER", "ADMIN", ...]
            if (authorities.isEmpty() && claims.get("roles") instanceof List) {
                List<String> roles = (List<String>) claims.get("roles");
                if (roles != null && !roles.isEmpty()) {
                    authorities = roles.stream()
                        .map(role -> role.startsWith("ROLE_") ? role : "ROLE_" + role)
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());
                }
            }
            
            // Format 3: "scope" or "scopes" as space-delimited string
            if (authorities.isEmpty()) {
                String scopes = null;
                if (claims.get("scope") instanceof String) {
                    scopes = (String) claims.get("scope");
                } else if (claims.get("scopes") instanceof String) {
                    scopes = (String) claims.get("scopes");
                }
                
                if (scopes != null && !scopes.isEmpty()) {
                    authorities = Arrays.stream(scopes.split("\\s+"))
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());
                }
            }
        } catch (Exception e) {
            log.warn("Error extracting authorities from token: {}", e.getMessage());
        }
        
        // Add default role if none found
        if (authorities.isEmpty()) {
            authorities.add(new SimpleGrantedAuthority("ROLE_USER"));
        }
        
        return authorities;
    }
    
    /**
     * Extract all claims from a token.
     */
    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(signingKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    /**
     * Validate JWT token.
     */
    public boolean validateToken(String token) {
        try {
            // Log token details for debugging
            logTokenDetails(token);
            
            // Validate token with signing key
            Jwts.parserBuilder().setSigningKey(signingKey).build().parseClaimsJws(token);
            return true;
        } catch (ExpiredJwtException e) {
            log.warn("JWT token expired");
            return false;
        } catch (UnsupportedJwtException | MalformedJwtException | SignatureException e) {
            log.warn("Invalid JWT token: {}", e.getMessage());
            return false;
        } catch (Exception e) {
            log.warn("JWT validation error: {}", e.getMessage());
            return false;
        }
    }
} 