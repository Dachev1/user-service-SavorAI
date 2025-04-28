package dev.idachev.userservice.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import jakarta.annotation.PreDestroy;

/**
 * Manages JWT token blacklist and user invalidations
 */
@Service
@Slf4j
public class TokenBlacklistService {

    private static final String USER_PREFIX = "invalidated_user::";
    private static final String JWT_PREFIX = "jwt_blacklist::";
    private static final Duration USER_INVALIDATION_DURATION = Duration.ofHours(24);
    private static final Duration FALLBACK_BLACKLIST_DURATION = Duration.ofHours(1);
    private static final Duration CLEANUP_INTERVAL = Duration.ofMinutes(15);

    private final Map<String, Instant> blacklistedTokens = new ConcurrentHashMap<>();
    private final Map<String, Instant> invalidatedUsers = new ConcurrentHashMap<>();
    private final ScheduledExecutorService cleanupExecutor;

    public TokenBlacklistService() {
        this.cleanupExecutor = new ScheduledThreadPoolExecutor(1);
        this.cleanupExecutor.scheduleAtFixedRate(
            this::cleanupExpiredEntries,
            CLEANUP_INTERVAL.toMillis(),
            CLEANUP_INTERVAL.toMillis(),
            TimeUnit.MILLISECONDS
        );
        log.info("Token blacklist service initialized");
    }

    /**
     * Blacklists a JWT until its expiry time
     */
    public void blacklistJwt(String jwt, long expiryTimestampMillis) {
        if (jwt == null || jwt.isBlank()) {
            log.warn("Cannot blacklist null/blank JWT");
            return;
        }

        Duration duration;
        long ttlMillis = expiryTimestampMillis - System.currentTimeMillis();
        
        if (ttlMillis > 0) {
            duration = Duration.ofMillis(ttlMillis);
        } else {
            log.warn("Invalid JWT expiry timestamp {}", expiryTimestampMillis);
            duration = FALLBACK_BLACKLIST_DURATION;
        }

        try {
            blacklistedTokens.put(JWT_PREFIX + jwt, Instant.now().plus(duration));
        } catch (Exception e) {
            log.error("Failed to blacklist JWT: {}", e.getMessage());
        }
    }

    /**
     * Checks if a JWT is blacklisted
     */
    public boolean isJwtBlacklisted(String jwt) {
        if (jwt == null || jwt.isBlank()) return false;
        
        try {
            String key = JWT_PREFIX + jwt;
            Instant expiry = blacklistedTokens.get(key);
            
            if (expiry != null) {
                if (expiry.isAfter(Instant.now())) {
                    return true;
                } else {
                    blacklistedTokens.remove(key);
                    return false;
                }
            }
            return false;
        } catch (Exception e) {
            log.error("JWT blacklist check failed: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Invalidates all tokens for a user
     */
    public void invalidateUserTokens(String userId) {
        if (userId == null || userId.isBlank()) {
            log.warn("Cannot invalidate null/blank user ID");
            return;
        }

        try {
            invalidatedUsers.put(USER_PREFIX + userId, 
                Instant.now().plus(USER_INVALIDATION_DURATION));
        } catch (Exception e) {
            log.error("Failed to invalidate user tokens: {}", e.getMessage());
        }
    }

    /**
     * Checks if a user's tokens are invalidated
     */
    public boolean isUserInvalidated(String userId) {
        if (userId == null || userId.isBlank()) return false;
        
        try {
            String key = USER_PREFIX + userId;
            Instant expiry = invalidatedUsers.get(key);
            
            if (expiry != null) {
                if (expiry.isAfter(Instant.now())) {
                    return true;
                } else {
                    invalidatedUsers.remove(key);
                    return false;
                }
            }
            return false;
        } catch (Exception e) {
            log.error("User invalidation check failed: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Cleans up expired entries
     */
    private void cleanupExpiredEntries() {
        try {
            Instant now = Instant.now();
            int tokenCount = 0;
            int userCount = 0;
            
            for (Map.Entry<String, Instant> entry : blacklistedTokens.entrySet()) {
                if (entry.getValue().isBefore(now)) {
                    blacklistedTokens.remove(entry.getKey());
                    tokenCount++;
                }
            }
            
            for (Map.Entry<String, Instant> entry : invalidatedUsers.entrySet()) {
                if (entry.getValue().isBefore(now)) {
                    invalidatedUsers.remove(entry.getKey());
                    userCount++;
                }
            }
            
            if (tokenCount > 0 || userCount > 0) {
                log.debug("Cleaned {} tokens and {} users", tokenCount, userCount);
            }
        } catch (Exception e) {
            log.error("Cleanup error: {}", e.getMessage());
        }
    }
    
    /**
     * Shutdown cleanup
     */
    @PreDestroy
    public void shutdown() {
        if (cleanupExecutor != null) {
            try {
                cleanupExecutor.shutdown();
                if (!cleanupExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                    cleanupExecutor.shutdownNow();
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }
} 