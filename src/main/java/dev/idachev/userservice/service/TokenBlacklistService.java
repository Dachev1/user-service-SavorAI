package dev.idachev.userservice.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import jakarta.annotation.PreDestroy;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Service for managing blacklisted JWT tokens
 * Implements TokenBlacklistServiceInterface following the Interface Segregation Principle
 */
@Service
@Slf4j
public class TokenBlacklistService {

    private final Map<String, Long> blacklistedTokens = new ConcurrentHashMap<>();
    private final Map<String, Long> userBlacklists = new ConcurrentHashMap<>();
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();
    private final long cleanupBatchSize;
    private final String jwtSecret;

    /**
     * Constructor with scheduled cleanup and configurable batch size
     */
    public TokenBlacklistService(
            @Value("${jwt.expiration:86400000}") long tokenExpirationMs,
            @Value("${jwt.blacklist.cleanup.batch-size:100}") long cleanupBatchSize,
            @Value("${jwt.secret}") String jwtSecret) {

        this.cleanupBatchSize = cleanupBatchSize;
        this.jwtSecret = jwtSecret;

        // Schedule cleanup task to run at 1/4 of the token expiration time
        long cleanupIntervalSeconds = Math.max(tokenExpirationMs / (4 * 1000), 60);

        scheduler.scheduleAtFixedRate(
                this::cleanupExpiredTokens,
                cleanupIntervalSeconds,
                cleanupIntervalSeconds,
                TimeUnit.SECONDS);

        log.info("Token blacklist service initialized with cleanup interval of {} seconds",
                cleanupIntervalSeconds);
    }

    @PreDestroy
    public void shutdown() {
        try {
            log.info("Shutting down token blacklist service");
            scheduler.shutdown(); // Change back to shutdown() for test compatibility
            if (!scheduler.awaitTermination(5, TimeUnit.SECONDS)) {
                log.warn("Token blacklist cleanup task did not terminate in time");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.warn("Interrupted while shutting down token blacklist service", e);
        }
    }

    /**
     * Blacklists a token with expiry time
     *
     * @param token           The token to blacklist
     * @param expiryTimestamp The timestamp when the token expires (in milliseconds)
     */
    public void blacklistToken(String token, long expiryTimestamp) {
        if (token.startsWith("user_tokens_invalidated:")) {
            userBlacklists.put(token, expiryTimestamp);
            log.info("Added user token invalidation: {}", token);
        } else {
            blacklistedTokens.put(token, expiryTimestamp);
            log.info("Token blacklisted until {}", new java.util.Date(expiryTimestamp));
        }

        // Clean up expired tokens when we add a new one
        cleanExpiredTokens();
    }

    /**
     * Checks if a token is blacklisted
     *
     * @param token The token to check
     * @return True if token is blacklisted, false otherwise
     */
    public boolean isBlacklisted(String token) {
        if (token == null) return false;

        // Check direct token blacklisting
        if (blacklistedTokens.containsKey(token)) {
            long expiryTime = blacklistedTokens.get(token);
            if (System.currentTimeMillis() > expiryTime) {
                // Token blacklisting has expired, remove it
                blacklistedTokens.remove(token);
                return false;
            }
            return true;
        }

        // Check if this token belongs to a user whose tokens have been invalidated
        try {
            // Extract user ID from JWT token and check user-specific blacklisting
            String userId = extractUserIdFromToken(token);
            if (userId != null) {
                String userKey = "user_tokens_invalidated:" + userId;
                if (userBlacklists.containsKey(userKey)) {
                    long expiryTime = userBlacklists.get(userKey);
                    if (System.currentTimeMillis() > expiryTime) {
                        // User blacklisting has expired, remove it
                        userBlacklists.remove(userKey);
                        return false;
                    }
                    return true;
                }
            }
        } catch (Exception e) {
            // If we can't extract the user ID, err on the side of caution
            log.warn("Error checking user-specific token invalidation: {}", e.getMessage());
        }

        return false;
    }

    /**
     * Extracts user ID from a JWT token
     * This is a simplified version - in production you'd use a proper JWT parser
     *
     * @param token The JWT token
     * @return The extracted user ID or null if not found
     */
    private String extractUserIdFromToken(String token) {
        try {
            // Use JwtConfig's proper implementation for token parsing
            Claims claims = Jwts.parser()
                    .setSigningKey(jwtSecret)
                    .parseClaimsJws(token)
                    .getBody();

            // First try user_id claim
            if (claims.containsKey("user_id")) {
                return claims.get("user_id", String.class);
            }

            // Then try userId claim
            if (claims.containsKey("userId")) {
                return claims.get("userId", String.class);
            }

            // Finally try standard sub claim which might contain the ID
            return claims.getSubject();
        } catch (Exception e) {
            log.debug("Error extracting user ID from token: {}", e.getMessage());
            return null;
        }
    }


    /**
     * Clean up expired tokens
     */
    private void cleanExpiredTokens() {
        long now = System.currentTimeMillis();

        // Clean up expired tokens
        blacklistedTokens.entrySet().removeIf(entry -> now > entry.getValue());

        // Clean up expired user blacklists
        userBlacklists.entrySet().removeIf(entry -> now > entry.getValue());
    }

    /**
     * Remove expired tokens from the blacklist in batches to prevent blocking
     */
    private void cleanupExpiredTokens() {
        try {
            long now = System.currentTimeMillis();
            int beforeSize = blacklistedTokens.size();

            if (beforeSize == 0) {
                return;
            }

            // but still limit the number of tokens processed per run
            int[] processCounter = {0};
            int maxToProcess = (int) Math.min(cleanupBatchSize, beforeSize);

            blacklistedTokens.entrySet().removeIf(entry -> {
                if (processCounter[0] >= maxToProcess) {
                    return false;
                }
                processCounter[0]++;
                return entry.getValue() < now;
            });

            int removedCount = beforeSize - blacklistedTokens.size();
            if (removedCount > 0) {
                log.info("Removed {} expired tokens from blacklist", removedCount);
            }
        } catch (Exception e) {
            log.error("Error during token blacklist cleanup", e);
        }
    }

    /**
     * Force cleanup of expired tokens immediately - used for testing
     */
    public void forceCleanupExpiredTokens() {
        cleanupExpiredTokens();
    }

} 