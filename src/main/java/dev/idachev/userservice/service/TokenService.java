package dev.idachev.userservice.service;

import dev.idachev.userservice.config.JwtConfig;
import dev.idachev.userservice.exception.AuthenticationException;
import dev.idachev.userservice.exception.InvalidTokenException;
import dev.idachev.userservice.model.User;
import dev.idachev.userservice.security.UserPrincipal;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.Date;
import java.util.UUID;

/**
 * Service for JWT token management
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class TokenService {

    private static final String USER_INVALIDATION_KEY_PREFIX = "user_tokens_invalidated:";
    // TODO: Externalize this duration via configuration (e.g., JwtConfig or application.properties)
    private static final Duration USER_INVALIDATION_DURATION = Duration.ofDays(30);

    private final JwtConfig jwtConfig;
    private final TokenBlacklistService tokenBlacklistService;

    /**
     * Generates a JWT token for a user
     */
    public String generateToken(UserDetails userDetails) {
        if (userDetails == null) {
            // Log warning and return empty token for safety
            log.warn("Attempted to generate token for null UserDetails");
            return "";
        }

        try {
            String token = jwtConfig.generateToken(userDetails);
            // Ensure token is never null, even if the JWT config fails
            return token != null ? token : "";
        } catch (Exception e) {
            // Log the exception and return empty token for safety
            log.error("Error generating token: {}", e.getMessage(), e);
            return "";
        }
    }

    /**
     * Validates a JWT token (signature, expiration, blacklist, user invalidation).
     * Propagates exceptions from underlying checks if they occur.
     */
    public boolean validateToken(String token, UserDetails userDetails) {
        String jwtToken = extractJwtToken(token);

        // Use new blacklist service method
        if (tokenBlacklistService.isJwtBlacklisted(jwtToken)) {
            log.debug("Token validation failed: Token is blacklisted");
            return false;
        }

        // Check user-specific invalidation
        if (userDetails instanceof UserPrincipal userPrincipal) {
            User user = userPrincipal.user();
            // Use new blacklist service method for user invalidation check
            if (tokenBlacklistService.isUserInvalidated(user.getId().toString())) {
                log.debug("Token validation failed: User {} tokens invalidated", user.getId());
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
        String jwtToken = extractJwtToken(token);
        if (jwtToken == null || jwtToken.isBlank()) {
            log.warn("Attempted to extract {} from null or blank token", claimName);
            throw new InvalidTokenException("Token cannot be null or blank");
        }
        try {
            return extractor.extract(jwtToken);
        } catch (ExpiredJwtException e) {
            log.warn("Error extracting {} from token: {}", claimName, e.getMessage()); // Log but re-throw specific type
            throw e; // Re-throw ExpiredJwtException directly
        } catch (Exception e) {
            log.warn("Error extracting {} from token: {}", claimName, e.getMessage());
            throw new InvalidTokenException("Invalid token format while extracting " + claimName, e);
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
     * Blacklists a specific JWT token until its expiry.
     * Extracts the expiry time internally.
     */
    public void blacklistToken(String token, Date expiry) { // Add expiry parameter
        if (token == null || token.isEmpty()) {
            throw new IllegalArgumentException("Token cannot be null or empty for blacklisting");
        }
        String jwtToken = extractJwtToken(token);
        try {
            // Use the passed expiry directly
            long expiryMillis = (expiry != null) ? expiry.getTime() : 0;
            tokenBlacklistService.blacklistJwt(jwtToken, expiryMillis);
        } catch (Exception e) { // Catch broader exceptions from blacklist service
            log.error("Failed to blacklist token {} with expiry {}: {}", jwtToken, expiry, e.getMessage(), e);
            // Decide if we should re-throw or handle
        }
    }

    /**
     * Checks if a JWT token is blacklisted.
     * Delegates to TokenBlacklistService.
     * Returns false if token is null/empty.
     */
    public boolean isJwtBlacklisted(String token) {
        if (token == null || token.isEmpty()) {
            return false;
        }
        String jwtToken = extractJwtToken(token);
        // Delegate to the correct method in TokenBlacklistService
        return tokenBlacklistService.isJwtBlacklisted(jwtToken);
    }

    /**
     * Checks if a user's tokens have been globally invalidated.
     * Delegates to TokenBlacklistService.
     */
    public boolean isUserInvalidated(UUID userId) {
        if (userId == null) {
            return false;
        }
        // Delegate to the correct method in TokenBlacklistService
        return tokenBlacklistService.isUserInvalidated(userId.toString());
    }

    /**
     * Refreshes a JWT token
     */
    public String refreshToken(String token, UserDetails userDetails) throws AuthenticationException {
        try {
            String jwtToken = extractJwtToken(token);

            // Use renamed local method which calls new blacklist service method
            if (isJwtBlacklisted(jwtToken)) {
                throw new AuthenticationException("Token is blacklisted or has been logged out");
            }

            // Check user invalidation status
            UUID userId = extractUserId(jwtToken); // Extract user ID first
            if (tokenBlacklistService.isUserInvalidated(userId.toString())) {
                log.warn("Token refresh attempt for invalidated user: {}", userId);
                throw new AuthenticationException("User session invalidated, please log in again.");
            }

            // Proceed with user details check
            if (userDetails instanceof UserPrincipal userPrincipal) {
                User user = userPrincipal.user();

                if (user.isBanned()) {
                    // Blacklist the current token if user is banned
                    Date expiry = extractExpiration(jwtToken);
                    if (expiry != null) blacklistToken(jwtToken, expiry); // Pass expiry
                    throw new AuthenticationException("User is banned");
                }

                if (user.getId().equals(userId)) {
                    // Blacklist the old token before issuing a new one
                    Date expiry = extractExpiration(jwtToken);
                    if (expiry != null) blacklistToken(jwtToken, expiry); // Pass expiry
                    // Generate new token
                    return generateToken(userDetails);
                } else {
                    // Token user ID does not match principal user ID
                    throw new AuthenticationException("Invalid token refresh attempt: User mismatch");
                }
            } else {
                throw new AuthenticationException("Invalid user principal type for token refresh");
            }
        } catch (ExpiredJwtException e) {
            // Allow refresh even if expired? Depends on policy. Current logic requires non-expired.
            // If refresh allowed for expired tokens, this check needs adjustment.
            throw new AuthenticationException("Token has expired", e);
        } catch (InvalidTokenException | JwtException e) {
            throw new AuthenticationException("Invalid token", e);
        } catch (AuthenticationException e) {
            throw e; // Re-throw specific auth exceptions
        } catch (Exception e) {
            // Catch-all for unexpected errors
            log.error("Unexpected error during token refresh: {}", e.getMessage(), e);
            throw new AuthenticationException("Token refresh failed due to an unexpected error", e);
        }
    }

    /**
     * Invalidates all tokens for a specific user by signaling the TokenBlacklistService.
     */
    public void invalidateUserTokens(UUID userId) { // Signature kept as UUID
        if (userId == null) {
            throw new IllegalArgumentException("User ID cannot be null for invalidating tokens");
        }
        try {
            // Delegate to TokenBlacklistService, converting UUID to String
            tokenBlacklistService.invalidateUserTokens(userId.toString());
        } catch (Exception e) {
            log.error("Error signaling token invalidation for user {}: {}", userId, e.getMessage(), e);
            // Optionally re-throw as a different exception type?
            throw new RuntimeException("Failed to signal token invalidation for user " + userId, e);
        }
    }

    /**
     * Extracts JWT token without the Bearer prefix
     */
    private String extractJwtToken(String token) {
        return token != null && token.startsWith("Bearer ") ? token.substring(7) : token;
    }
} 