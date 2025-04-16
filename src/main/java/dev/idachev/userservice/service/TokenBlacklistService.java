package dev.idachev.userservice.service;

import jakarta.annotation.PreDestroy;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
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

    private final ConcurrentHashMap<String, LocalDateTime> blacklistedTokens = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Long> userBlacklists = new ConcurrentHashMap<>();
    private final ScheduledExecutorService cleanupExecutor = Executors.newSingleThreadScheduledExecutor();
    private final java.security.Key signingKey;
    private volatile boolean isShutdown = false;

    // Default expiration time is 24 hours
    @Value("${jwt.expiration:86400000}")
    private long jwtExpiration;
    
    // How often to clean up expired tokens (default: 1 hour)
    private final long cleanupInterval;

    @Autowired
    public TokenBlacklistService(@Value("${jwt.blacklist.cleanup-interval:3600}") long cleanupInterval,
                                @Value("${jwt.secret}") String jwtSecret) {
        this.cleanupInterval = cleanupInterval;

        // Create key once during initialization
        this.signingKey = io.jsonwebtoken.security.Keys.hmacShaKeyFor(
                jwtSecret.getBytes(java.nio.charset.StandardCharsets.UTF_8));

        // Schedule cleanup task to run at 1/4 of the token expiration time or at least every minute
        long cleanupIntervalSeconds = Math.max(jwtExpiration / (4 * 1000), 60);

        cleanupExecutor.scheduleAtFixedRate(
                this::cleanExpiredTokens,
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
            isShutdown = true;
            cleanupExecutor.shutdownNow();
            if (!cleanupExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                log.warn("Token blacklist cleanup task did not terminate in time");
            }
        } catch (InterruptedException e) {
            cleanupExecutor.shutdownNow();
            Thread.currentThread().interrupt();
            log.warn("Interrupted while shutting down token blacklist service", e);
        }
    }

    /**
     * Blacklists a token with expiry time
     */
    public void blacklistToken(String token, long expiryTimestamp) {
        if (token == null) {
            log.warn("Attempted to blacklist null token");
            return;
        }
        
        if (token.startsWith("user_tokens_invalidated:")) {
            userBlacklists.put(token, expiryTimestamp);
            log.info("Added user token invalidation: {}", token);
        } else {
            LocalDateTime expiryDateTime;
            
            // Special case for zero expiry - default to 24 hours in the future
            if (expiryTimestamp == 0L) {
                expiryDateTime = LocalDateTime.now().plusHours(24);
                log.info("Token with zero expiry blacklisted until {}", expiryDateTime);
            } else {
                try {
                    // Convert milliseconds timestamp to LocalDateTime
                    expiryDateTime = LocalDateTime.now().plusSeconds((expiryTimestamp - System.currentTimeMillis()) / 1000);
                    log.info("Token blacklisted until {}", expiryDateTime);
                } catch (Exception e) {
                    // Fallback to 1 hour from now if conversion fails
                    log.warn("Error processing timestamp {}, using fallback expiry", expiryTimestamp);
                    expiryDateTime = LocalDateTime.now().plusHours(1);
                }
            }
            
            blacklistedTokens.put(token, expiryDateTime);
        }
    }

    /**
     * Checks if a token is blacklisted
     */
    public boolean isBlacklisted(String token) {
        if (token == null) {
            return false;
        }

        if (token.startsWith("user_tokens_invalidated:")) {
            // For user blacklists, just check if the token exists in the map
            return userBlacklists.containsKey(token);
        }

        // For regular tokens, just check if the token exists in the map
        // The expiry check is handled during cleanup
        return blacklistedTokens.containsKey(token);
    }

    /**
     * Clean up expired tokens
     */
    private void cleanExpiredTokens() {
        if (isShutdown) {
            return;
        }
        
        LocalDateTime now = LocalDateTime.now();
        int removedCount = 0;

        // Clean up expired tokens
        for (String token : blacklistedTokens.keySet()) {
            LocalDateTime expiry = blacklistedTokens.get(token);
            if (expiry != null && (now.isAfter(expiry) || now.isEqual(expiry))) {
                blacklistedTokens.remove(token);
                removedCount++;
            }
        }

        // Clean up expired user blacklists
        long currentTime = System.currentTimeMillis();
        int removedUserBlacklists = 0;
        
        for (String key : userBlacklists.keySet()) {
            Long expiry = userBlacklists.get(key);
            if (expiry != null && currentTime > expiry) {
                userBlacklists.remove(key);
                removedUserBlacklists++;
            }
        }

        if (removedCount > 0 || removedUserBlacklists > 0) {
            log.info("Cleaned up {} expired tokens and {} user blacklists", 
                    removedCount, removedUserBlacklists);
        }
    }

    /**
     * Force cleanup of expired tokens immediately - used for testing
     */
    public void forceCleanupExpiredTokens() {
        if (!isShutdown) {
            cleanExpiredTokens();
        } else {
            log.info("Skipping cleanup as service is shut down");
        }
    }

} 