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
    
    /**
     * Constructor with scheduled cleanup
     */
    public TokenBlacklistService(
            @Value("${jwt.expiration:86400000}") long tokenExpirationMs) {
        
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
        scheduler.shutdown();
        log.info("Token blacklist service shutdown");
    }

    /**
     * Add a token to the blacklist
     * @param token The JWT token to blacklist
     * @param expiryTime Token expiration time in milliseconds (epoch)
     */
    public void blacklistToken(String token, Long expiryTime) {
        if (token != null && expiryTime != null) {
            blacklistedTokens.put(token, expiryTime);
            log.debug("Token added to blacklist");
        }
    }

    /**
     * Check if a token is blacklisted
     * @param token The JWT token to check
     * @return true if the token is blacklisted, false otherwise
     */
    public boolean isBlacklisted(String token) {
        return token != null && blacklistedTokens.containsKey(token);
    }

    /**
     * Remove expired tokens from the blacklist
     */
    private void cleanupExpiredTokens() {
        long now = System.currentTimeMillis();
        int beforeSize = blacklistedTokens.size();
        blacklistedTokens.entrySet().removeIf(entry -> entry.getValue() < now);
        int removedCount = beforeSize - blacklistedTokens.size();
        
        if (removedCount > 0) {
            log.info("Removed {} expired tokens from blacklist", removedCount);
        }
    }
} 