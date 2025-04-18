package dev.idachev.userservice.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;

/**
 * Service for managing blacklisted JWT tokens and user invalidations using Redis.
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class TokenBlacklistService {

    // Prefix for keys storing invalidated user tokens
    private static final String USER_INVALIDATION_KEY_PREFIX = "invalidated_user::";
    // Prefix for keys storing blacklisted JWTs
    private static final String JWT_BLACKLIST_KEY_PREFIX = "jwt_blacklist::";
    // Default duration for user invalidation marker (e.g., 30 days) - consider making configurable
    private static final Duration USER_INVALIDATION_DURATION = Duration.ofDays(30);
    // Fallback blacklist duration if JWT expiry calculation fails
    private static final Duration FALLBACK_BLACKLIST_DURATION = Duration.ofHours(1);

    private final StringRedisTemplate redisTemplate;
    // private final JwtConfig jwtConfig; // Inject if default JWT expiration needed as fallback

    /**
     * Blacklists a specific JWT until its natural expiry time.
     *
     * @param jwt                   The raw JWT string to blacklist.
     * @param expiryTimestampMillis The original expiry timestamp of the JWT in milliseconds since epoch.
     */
    public void blacklistJwt(String jwt, long expiryTimestampMillis) {
        if (jwt == null || jwt.isBlank()) {
            log.warn("Attempted to blacklist null or blank JWT");
            return; // Or throw IllegalArgumentException
        }

        long ttlMillis = expiryTimestampMillis - System.currentTimeMillis();
        Duration duration;

        if (ttlMillis > 0) {
            duration = Duration.ofMillis(ttlMillis);
            // Add a small buffer to account for clock skew or processing time? Optional.
        } else {
            // Token already expired or expiry is invalid, blacklist for a short fallback duration
            log.warn("JWT expiry timestamp {} is in the past or invalid. Blacklisting for fallback duration: {}",
                    expiryTimestampMillis, FALLBACK_BLACKLIST_DURATION);
            duration = FALLBACK_BLACKLIST_DURATION;
        }

        // Ensure duration is not excessively long (sanity check, optional)
        // Duration maxDuration = Duration.ofDays(someConfiguredMaxDays); 
        // if (duration.compareTo(maxDuration) > 0) { duration = maxDuration; } 

        try {
            String key = JWT_BLACKLIST_KEY_PREFIX + jwt;
            // Set a value (can be empty string or "1") with the calculated TTL
            redisTemplate.opsForValue().set(key, "blacklisted", duration);
            log.debug("JWT blacklisted with TTL {}: {}", duration, key);
        } catch (Exception e) {
            log.error("Failed to blacklist JWT in Redis: {}", e.getMessage(), e);
            // Decide if exception should be propagated
            // throw new RuntimeException("Failed to blacklist token", e);
        }
    }

    /**
     * Checks if a specific JWT is present in the blacklist (i.e., has an entry in Redis).
     *
     * @param jwt The raw JWT string to check.
     * @return true if the JWT is blacklisted, false otherwise.
     */
    public boolean isJwtBlacklisted(String jwt) {
        if (jwt == null || jwt.isBlank()) {
            return false; // Cannot be blacklisted
        }
        try {
            String key = JWT_BLACKLIST_KEY_PREFIX + jwt;
            Boolean hasKey = redisTemplate.hasKey(key);
            return Boolean.TRUE.equals(hasKey);
        } catch (Exception e) {
            log.error("Failed to check JWT blacklist status in Redis: {}", e.getMessage(), e);
            // Fail safe? Assume blacklisted on error?
            // Or return false and rely on standard expiry? Returning false seems safer.
            return false;
        }
    }

    /**
     * Invalidates all tokens for a specific user by adding a marker in Redis.
     *
     * @param userId The ID of the user whose tokens should be invalidated.
     */
    public void invalidateUserTokens(String userId) {
        if (userId == null || userId.isBlank()) {
            log.warn("Attempted to invalidate tokens for null or blank user ID");
            return; // Or throw IllegalArgumentException
        }

        try {
            String key = USER_INVALIDATION_KEY_PREFIX + userId;
            redisTemplate.opsForValue().set(key, "invalidated", USER_INVALIDATION_DURATION);
            log.debug("User token invalidation marker set for user {} with TTL {}", userId, USER_INVALIDATION_DURATION);
        } catch (Exception e) {
            log.error("Failed to set user token invalidation marker in Redis for user {}: {}", userId, e.getMessage(), e);
            // Decide if exception should be propagated
            // throw new RuntimeException("Failed to invalidate user tokens", e);
        }
    }

    /**
     * Checks if a user's tokens have been globally invalidated via a marker in Redis.
     *
     * @param userId The ID of the user to check.
     * @return true if the user's tokens are marked as invalidated, false otherwise.
     */
    public boolean isUserInvalidated(String userId) {
        if (userId == null || userId.isBlank()) {
            return false;
        }
        try {
            String key = USER_INVALIDATION_KEY_PREFIX + userId;
            Boolean hasKey = redisTemplate.hasKey(key);
            return Boolean.TRUE.equals(hasKey);
        } catch (Exception e) {
            log.error("Failed to check user token invalidation status in Redis for user {}: {}", userId, e.getMessage(), e);
            // Fail safe? Assume invalidated on error?
            // Returning false seems safer, relying on JWT expiry/blacklist.
            return false;
        }
    }

    // Cleanup executor, maps, PreDestroy logic, etc. removed
    // forceCleanupExpiredTokens removed
} 