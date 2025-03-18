package dev.idachev.userservice.service;

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
 */
@Service
@Slf4j
public class TokenBlacklistService {

    private final Map<String, Long> blacklistedTokens = new ConcurrentHashMap<>();
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();
    private final long cleanupBatchSize;

    /**
     * Constructor with scheduled cleanup and configurable batch size
     */
    public TokenBlacklistService(
            @Value("${jwt.expiration:86400000}") long tokenExpirationMs,
            @Value("${jwt.blacklist.cleanup.batch-size:100}") long cleanupBatchSize) {

        this.cleanupBatchSize = cleanupBatchSize;

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
     * Add a token to the blacklist
     *
     * @param token      The JWT token to blacklist
     * @param expiryTime Token expiration time in milliseconds (epoch)
     */
    public void blacklistToken(String token, Long expiryTime) {
        if (token == null || expiryTime == null) {
            return;
        }

        // For tests - allow blacklisting expired tokens
        blacklistedTokens.put(token, expiryTime);
        log.debug("Token added to blacklist, will expire at {}", expiryTime);
    }

    /**
     * Check if a token is blacklisted
     *
     * @param token The JWT token to check
     * @return true if the token is blacklisted, false otherwise
     */
    public boolean isBlacklisted(String token) {
        return token != null && blacklistedTokens.containsKey(token);
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

            // Only process at most cleanupBatchSize tokens per run to avoid long-running operations
            int processed = 0;
            for (Map.Entry<String, Long> entry : blacklistedTokens.entrySet()) {
                if (entry.getValue() < now) {
                    blacklistedTokens.remove(entry.getKey());
                }

                processed++;
                if (processed >= cleanupBatchSize) {
                    break;
                }
            }

            int removedCount = beforeSize - blacklistedTokens.size();
            if (removedCount > 0) {
                log.info("Removed {} expired tokens from blacklist", removedCount);
            }
        } catch (Exception e) {
            log.error("Error during token blacklist cleanup", e);
        }
    }
} 