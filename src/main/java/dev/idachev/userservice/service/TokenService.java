package dev.idachev.userservice.service;

import dev.idachev.userservice.config.JwtConfig;
import dev.idachev.userservice.exception.AuthenticationException;
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
     *
     * @param userDetails User details
     * @return JWT token
     */
    public String generateToken(UserDetails userDetails) {
        return jwtConfig.generateToken(userDetails);
    }

    /**
     * Validates a JWT token
     *
     * @param token       JWT token
     * @param userDetails User details
     * @return True if token is valid
     */
    public boolean validateToken(String token, UserDetails userDetails) {
        // First check if token is blacklisted
        if (isTokenBlacklisted(token)) {
            return false;
        }

        // If not blacklisted, proceed with normal validation
        return jwtConfig.validateToken(token, userDetails);
    }

    /**
     * Extracts user ID from a token
     *
     * @param token JWT token
     * @return User ID
     */
    public UUID extractUserId(String token) {
        return jwtConfig.extractUserId(token);
    }

    /**
     * Extracts username from a token
     *
     * @param token JWT token
     * @return Username
     */
    public String extractUsername(String token) {
        return jwtConfig.extractUsername(token);
    }

    /**
     * Extracts expiration date from a token
     *
     * @param token JWT token
     * @return Expiration date
     */
    public Date extractExpiration(String token) {
        return jwtConfig.extractExpiration(token);
    }

    /**
     * Blacklists a token
     *
     * @param token JWT token
     * @return True if blacklisting was successful
     */
    public boolean blacklistToken(String token) {
        if (token == null || !token.startsWith("Bearer ")) {
            return false;
        }

        try {
            String jwtToken = token.substring(7);
            Date expiryDate = extractExpiration(jwtToken);

            if (expiryDate != null) {
                tokenBlacklistService.blacklistToken(jwtToken, expiryDate.getTime());
                log.info("Token blacklisted successfully. Forcing logout for security.");
                return true;
            }
            return false;
        } catch (ExpiredJwtException e) {
            // Token already expired, no need to blacklist
            return true;
        } catch (JwtException e) {
            log.warn("Invalid JWT token during blacklisting: {}", e.getMessage());
            return false;
        } catch (Exception e) {
            log.error("Error blacklisting token: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Checks if a token is blacklisted
     *
     * @param token JWT token
     * @return True if token is blacklisted
     */
    public boolean isTokenBlacklisted(String token) {
        return tokenBlacklistService.isBlacklisted(token);
    }

    /**
     * Refreshes a JWT token
     *
     * @param token       Original token
     * @param userDetails User details
     * @return New JWT token
     */
    public String refreshToken(String token, UserDetails userDetails) throws AuthenticationException {
        try {
            if (isTokenBlacklisted(token)) {
                throw new AuthenticationException("Token is blacklisted");
            }

            UUID userId = extractUserId(token);

            if (userDetails instanceof UserPrincipal userPrincipal) {
                User user = userPrincipal.user();

                // Check if user is banned
                if (user.isBanned()) {
                    // If user is banned, blacklist the token but don't issue a new one
                    blacklistToken("Bearer " + token);
                    throw new AuthenticationException("User is banned");
                }

                // Validate that the user ID matches
                if (user.getId().equals(userId)) {
                    // Blacklist the old token
                    blacklistToken("Bearer " + token);

                    // Generate a new token
                    return generateToken(userDetails);
                } else {
                    throw new AuthenticationException("Invalid token refresh attempt");
                }
            } else {
                throw new AuthenticationException("Invalid user principal");
            }
        } catch (ExpiredJwtException e) {
            log.warn("Expired token in refreshToken: {}", e.getMessage());
            throw new AuthenticationException("Expired token", e);
        } catch (JwtException e) {
            log.warn("Invalid token in refreshToken: {}", e.getMessage());
            throw new AuthenticationException("Invalid token", e);
        } catch (AuthenticationException e) {
            throw e;
        } catch (Exception e) {
            log.error("Error refreshing token: {}", e.getMessage());
            throw new AuthenticationException("Token refresh failed", e);
        }
    }

    /**
     * Invalidates all tokens for a specific user
     *
     * @param userId The user ID whose tokens should be invalidated
     */
    public void invalidateUserTokens(UUID userId) {
        if (userId == null) {
            log.warn("Attempted to invalidate tokens for null user ID");
            return;
        }

        try {
            log.info("Invalidating all tokens for user: {}", userId);

            // Blacklist a user-specific key that will be checked during token validation
            String userSpecificToken = "user_tokens_invalidated:" + userId.toString();
            tokenBlacklistService.blacklistToken(userSpecificToken, System.currentTimeMillis() + (30L * 24 * 60 * 60 * 1000)); // 30 days expiry

        } catch (Exception e) {
            log.error("Error invalidating tokens for user {}: {}", userId, e.getMessage());
        }
    }
} 