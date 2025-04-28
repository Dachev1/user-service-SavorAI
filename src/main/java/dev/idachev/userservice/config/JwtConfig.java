package dev.idachev.userservice.config;

import dev.idachev.userservice.model.User;
import dev.idachev.userservice.security.UserPrincipal;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;

@Slf4j
@Component
public class JwtConfig {

    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.expiration}")
    private Long expiration;

    private Key signingKey;

    public Key getSigningKey() {
        return signingKey;
    }

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
            return extractUserIdFromClaims(claims);
        } catch (JwtException e) {
             log.warn("Failed to extract user ID from token: {}", e.getMessage());
             throw e;
        } catch (Exception e) {
             log.error("Unexpected error extracting userId: {}", e.getMessage(), e);
             throw new JwtException("Failed to extract userId due to unexpected error", e);
        }
    }

    /**
     * Extracts User ID from pre-parsed claims.
     */
    public UUID extractUserIdFromClaims(Claims claims) {
        try {
            String userIdStr = claims.get("userId", String.class);
            if (userIdStr == null || userIdStr.isBlank()) {
                log.warn("User ID claim (userId) is missing or blank in claims");
                return null;
            }
            return UUID.fromString(userIdStr);
        } catch (IllegalArgumentException e) {
            log.warn("Invalid User ID format in token claim: {}", e.getMessage());
            return null;
        } catch (Exception e) {
             log.error("Unexpected error extracting userId from claims: {}", e.getMessage(), e);
             return null;
        }
    }
    
    /**
     * Extracts roles/authorities from the token.
     * Handles various common claim formats (roles list, authorities list, scope string).
     */
    @SuppressWarnings("unchecked")
    public List<GrantedAuthority> extractRoles(String token) {
         try {
            Claims claims = extractAllClaims(token);
            List<GrantedAuthority> authorities = new ArrayList<>();

            // Check for "roles" claim (preferred for this service)
            if (claims.get("roles") instanceof List) {
                List<?> rolesRaw = (List<?>) claims.get("roles");
                if (rolesRaw != null) {
                    authorities = rolesRaw.stream()
                            .filter(String.class::isInstance)
                            .map(String.class::cast)
                            .filter(role -> !role.isBlank())
                            .map(role -> role.startsWith("ROLE_") ? role : "ROLE_" + role.toUpperCase())
                            .map(SimpleGrantedAuthority::new)
                            .collect(Collectors.toList());
                }
            }

            // Fallback: Check for "authorities" claim (common Spring Security format)
             if (authorities.isEmpty() && claims.get("authorities") instanceof List) {
                List<?> authsListRaw = (List<?>) claims.get("authorities");
                if (authsListRaw != null && !authsListRaw.isEmpty()) {
                    // Handle map format: {"authority": "ROLE_..."}
                    if (authsListRaw.get(0) instanceof LinkedHashMap) {
                         List<LinkedHashMap<String, String>> authsList = (List<LinkedHashMap<String, String>>) authsListRaw;
                         authorities = authsList.stream()
                                 .filter(map -> map != null && map.containsKey("authority"))
                                 .map(map -> new SimpleGrantedAuthority(map.get("authority")))
                                 .collect(Collectors.toList());
                    } 
                    // Handle simple string list format: ["ROLE_..."]
                    else if (authsListRaw.get(0) instanceof String) {
                         List<String> authsList = (List<String>) authsListRaw;
                         authorities = authsList.stream()
                                 .filter(auth -> auth != null && !auth.isBlank())
                                 .map(SimpleGrantedAuthority::new)
                                 .collect(Collectors.toList());
                    }
                }
            }

            // Fallback: Check for "scope" or "scopes" claim (OAuth2 format)
            if (authorities.isEmpty()) {
                String scopes = null;
                if (claims.get("scope") instanceof String) {
                    scopes = (String) claims.get("scope");
                } else if (claims.get("scopes") instanceof String) {
                    scopes = (String) claims.get("scopes");
                }
                if (scopes != null && !scopes.isBlank()) {
                    authorities = Arrays.stream(scopes.split("\\s+"))
                            .filter(scope -> !scope.isBlank())
                            .map(scope -> scope.startsWith("ROLE_") ? scope : "ROLE_" + scope.toUpperCase())
                            .map(SimpleGrantedAuthority::new)
                            .collect(Collectors.toList());
                }
            }
            
             if (authorities.isEmpty()) {
                 log.trace("No roles or authorities found in token claims.");
                 return Collections.emptyList();
             }

            return authorities;
        } catch (Exception e) {
            log.warn("Error extracting roles/authorities from token: {}", e.getMessage());
            return Collections.emptyList();
        }
    }

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    // Make this public for the filter
    public Claims extractAllClaims(String token) { 
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
            log.warn("Invalid JWT signature or format: {}", e.getMessage());
            throw e;
        } catch (UnsupportedJwtException e) {
            log.warn("JWT token is unsupported: {}", e.getMessage());
            throw e;
        } catch (IllegalArgumentException e) {
            log.warn("JWT claims string is empty or invalid: {}", e.getMessage());
            throw e;
        } catch (Exception e) {
            log.error("Error parsing JWT token: {}", e.getMessage(), e);
            throw new JwtException("Failed to parse JWT token", e);
        }
    }

    private boolean isTokenExpired(String token) {
        try {
            return extractExpiration(token).before(new Date());
        } catch (ExpiredJwtException e) {
            return true;
        }
    }
    
    /**
     * Validates standard claims for a service token (e.g., expiration).
     * Add checks for issuer, audience etc. as needed.
     */
     public boolean validateServiceTokenClaims(Claims claims) {
         try {
             // Check expiration
             if (claims.getExpiration() == null || claims.getExpiration().before(new Date())) {
                 log.warn("Service token has expired.");
                 return false;
             }
             // Optional: Check issuer
             // String expectedIssuer = "recipe-service"; 
             // if (!expectedIssuer.equals(claims.getIssuer())) {
             //     log.warn("Service token issuer mismatch. Expected: {}, Actual: {}", expectedIssuer, claims.getIssuer());
             //     return false;
             // }
             // Optional: Check audience
             // String expectedAudience = "user-service";
             // if (!expectedAudience.equals(claims.getAudience())) {
             //      log.warn("Service token audience mismatch. Expected: {}, Actual: {}", expectedAudience, claims.getAudience());
             //      return false;
             // }

            return true;
        } catch (Exception e) {
            log.error("Error validating service token claims: {}", e.getMessage(), e);
            return false;
        }
    }

    // validateToken remains for user tokens
    public boolean validateToken(String token, UserDetails userDetails) {
        if (token == null || token.isBlank() || userDetails == null) {
            return false;
        }
        
        try {
            final String username = extractUsername(token);
             // Also check if user ID from token matches UserDetails if available
             UUID userIdFromToken = extractUserId(token);
             UUID userIdFromDetails = null;
             if (userDetails instanceof UserPrincipal principal) {
                 userIdFromDetails = principal.user().getId();
             }
            
            return username != null && 
                   username.equals(userDetails.getUsername()) && 
                   (userIdFromDetails == null || userIdFromToken == null || userIdFromDetails.equals(userIdFromToken)) &&
                   !isTokenExpired(token) && 
                   userDetails.isEnabled();
        } catch (ExpiredJwtException e) {
             log.debug("User token validation failed (Expired): {}", e.getMessage());
            return false;
        } catch (JwtException e) {
             log.warn("User token validation failed (JWT Exception): {}", e.getMessage());
             return false;
        } catch (Exception e) {
            log.error("Unexpected error during user token validation: {}", e.getMessage(), e);
            return false;
        }
    }
} 
