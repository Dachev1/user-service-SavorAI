package dev.idachev.userservice.service;

import dev.idachev.userservice.config.JwtConfig;
import dev.idachev.userservice.exception.AuthenticationException;
import dev.idachev.userservice.exception.InvalidTokenException;
import dev.idachev.userservice.model.User;
import dev.idachev.userservice.security.UserPrincipal;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.UUID;

/**
 * Service for JWT token management
 */
@Service
@Slf4j
public class TokenService {

    private final JwtConfig jwtConfig;
    private final TokenBlacklistService tokenBlacklistService;

    @Autowired
    public TokenService(JwtConfig jwtConfig, TokenBlacklistService tokenBlacklistService) {
        this.jwtConfig = jwtConfig;
        this.tokenBlacklistService = tokenBlacklistService;
    }

    /**
     * Generates a JWT token for a user
     */
    public String generateToken(UserDetails userDetails) {
        return jwtConfig.generateToken(userDetails);
    }

    /**
     * Validates a JWT token
     */
    public boolean validateToken(String token, UserDetails userDetails) {
        String jwtToken = extractJwtToken(token);

        if (isTokenBlacklisted(jwtToken)) {
            return false;
        }

        if (userDetails instanceof UserPrincipal userPrincipal) {
            User user = userPrincipal.user();
            String userInvalidationKey = "user_tokens_invalidated:" + user.getId().toString();
            if (tokenBlacklistService.isBlacklisted(userInvalidationKey)) {
                return false;
            }
        }

        return jwtConfig.validateToken(jwtToken, userDetails);
    }

    /**
     * Extracts user ID from a token
     */
    public UUID extractUserId(String token) {
        return extractClaim(token, jwtConfig::extractUserId, "user ID");
    }

    /**
     * Extracts username from a token
     */
    public String extractUsername(String token) {
        return extractClaim(token, jwtConfig::extractUsername, "username");
    }

    /**
     * Extracts expiration date from a token
     */
    public Date extractExpiration(String token) {
        return extractClaim(token, jwtConfig::extractExpiration, "expiration date");
    }

    /**
     * Generic method to extract claims from token with proper error handling
     */
    private <T> T extractClaim(String token, ClaimExtractor<T> extractor, String claimName) {
        try {
            return extractor.extract(extractJwtToken(token));
        } catch (Exception e) {
            log.warn("Error extracting {} from token: {}", claimName, e.getMessage());
            throw new InvalidTokenException("Invalid token format", e);
        }
    }

    /**
     * Functional interface for claim extraction
     */
    @FunctionalInterface
    private interface ClaimExtractor<T> {
        T extract(String token);
    }

    /**
     * Blacklists a token
     */
    public boolean blacklistToken(String token) {
        try {
            String jwtToken = extractJwtToken(token);
            if (jwtToken == null) {
                log.warn("Cannot blacklist null token");
                return false;
            }

            Date expirationDate = extractExpiration(jwtToken);
            tokenBlacklistService.blacklistToken(jwtToken, expirationDate.getTime());
            log.info("Token blacklisted successfully");
            return true;
        } catch (InvalidTokenException e) {
            log.error("Failed to blacklist invalid token: {}", e.getMessage());
            return false;
        } catch (Exception e) {
            log.error("Failed to blacklist token: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Checks if a token is blacklisted
     */
    public boolean isTokenBlacklisted(String token) {
        return tokenBlacklistService.isBlacklisted(extractJwtToken(token));
    }

    /**
     * Refreshes a JWT token
     */
    public String refreshToken(String token, UserDetails userDetails) throws AuthenticationException {
        try {
            String jwtToken = extractJwtToken(token);

            if (isTokenBlacklisted(jwtToken)) {
                throw new AuthenticationException("Token is blacklisted or has been logged out");
            }

            UUID userId = extractUserId(jwtToken);

            if (userDetails instanceof UserPrincipal userPrincipal) {
                User user = userPrincipal.user();

                if (user.isBanned()) {
                    blacklistToken(jwtToken);
                    throw new AuthenticationException("User is banned");
                }

                if (user.getId().equals(userId)) {
                    blacklistToken(jwtToken);
                    return generateToken(userDetails);
                } else {
                    throw new AuthenticationException("Invalid token refresh attempt");
                }
            } else {
                throw new AuthenticationException("Invalid user principal");
            }
        } catch (ExpiredJwtException e) {
            throw new AuthenticationException("Expired token", e);
        } catch (JwtException e) {
            throw new AuthenticationException("Invalid token", e);
        } catch (AuthenticationException e) {
            throw e;
        } catch (Exception e) {
            throw new AuthenticationException("Token refresh failed", e);
        }
    }

    /**
     * Invalidates all tokens for a specific user
     */
    public void invalidateUserTokens(UUID userId) {
        if (userId == null) {
            log.warn("Attempted to invalidate tokens for null user ID");
            return;
        }

        try {
            String userSpecificToken = "user_tokens_invalidated:" + userId.toString();
            // 30 days expiry for user token invalidation
            long expiryTime = System.currentTimeMillis() + (30L * 24 * 60 * 60 * 1000);
            tokenBlacklistService.blacklistToken(userSpecificToken, expiryTime);
        } catch (Exception e) {
            log.error("Error invalidating tokens for user {}: {}", userId, e.getMessage());
        }
    }
    
    /**
     * Extracts JWT token without the Bearer prefix
     */
    private String extractJwtToken(String token) {
        if (token != null && token.startsWith("Bearer ")) {
            return token.substring(7);
        }
        return token;
    }
} 