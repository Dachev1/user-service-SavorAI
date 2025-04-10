package dev.idachev.userservice.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@ExtendWith(MockitoExtension.class)
class TokenBlacklistServiceUTest {

    private TokenBlacklistService tokenBlacklistService;

    private String testToken;
    private long testExpiryTime;

    @BeforeEach
    void setUp() {
        // Use actual primitive values instead of mocks
        long cleanupIntervalSeconds = 60L; // 1 minute
        long cleanupBatchSize = 100L;
        String jwtSecret = "testsecrettestsecrettestsecrettestsecrettestsecret"; // Test secret matching the one in application-test.yml

        // Directly create service with actual values
        tokenBlacklistService = new TokenBlacklistService(cleanupIntervalSeconds, cleanupBatchSize, jwtSecret);

        testToken = "test.jwt.token";
        testExpiryTime = System.currentTimeMillis() + 3600000; // 1 hour from now
    }

    @Test
    void blacklistToken_WithValidTokenAndExpiry_AddsToBlacklist() {
        // When
        tokenBlacklistService.blacklistToken(testToken, testExpiryTime);

        // Then - verify token is blacklisted
        assertTrue(tokenBlacklistService.isBlacklisted(testToken), "Token should be blacklisted");
    }

    @Test
    void blacklistToken_WithNullToken_DoesNotAddToBlacklist() {
        // When
        tokenBlacklistService.blacklistToken(null, testExpiryTime);
        
        // Then
        assertFalse(tokenBlacklistService.isBlacklisted(null));
    }

    @Test
    void blacklistToken_WithZeroExpiry_StillAddsToBlacklist() {
        // When
        tokenBlacklistService.blacklistToken(testToken, 0L);

        // Then
        assertTrue(tokenBlacklistService.isBlacklisted(testToken), "Token should be blacklisted even with zero expiry");
    }

    @Test
    void isBlacklisted_WithBlacklistedToken_ReturnsTrue() {
        // Given
        tokenBlacklistService.blacklistToken(testToken, testExpiryTime);

        // When/Then
        assertTrue(tokenBlacklistService.isBlacklisted(testToken), "Blacklisted token should return true");
    }

    @Test
    void isBlacklisted_WithNonBlacklistedToken_ReturnsFalse() {
        // When/Then
        assertFalse(tokenBlacklistService.isBlacklisted(testToken));
    }

    @Test
    void isBlacklisted_WithNullToken_ReturnsFalse() {
        // When/Then
        assertFalse(tokenBlacklistService.isBlacklisted(null));
    }

    @Test
    void cleanupExpiredTokens_RemovesExpiredTokens() throws InterruptedException {
        // Given
        String expiredToken = "expired.token";
        // Use a timestamp far in the past to ensure it's expired
        long pastExpiry = System.currentTimeMillis() - 60000; // 1 minute ago
        
        // Add an expired token and a non-expired token
        tokenBlacklistService.blacklistToken(expiredToken, pastExpiry);
        tokenBlacklistService.blacklistToken(testToken, testExpiryTime);
        
        // Both should be blacklisted initially
        assertTrue(tokenBlacklistService.isBlacklisted(expiredToken), "Expired token should be blacklisted initially");
        assertTrue(tokenBlacklistService.isBlacklisted(testToken), "Non-expired token should be blacklisted");

        // When
        // Force cleanup to run immediately
        tokenBlacklistService.forceCleanupExpiredTokens();
        
        // Then
        assertFalse(tokenBlacklistService.isBlacklisted(expiredToken), "Expired token should be removed after cleanup");
        assertTrue(tokenBlacklistService.isBlacklisted(testToken), "Non-expired token should remain blacklisted");
    }

    @Test
    void shutdown_StopsCleanupTask() throws InterruptedException {
        // Given
        String expiredToken = "expired.token";
        long pastExpiry = System.currentTimeMillis() - 60000; // 1 minute ago
        tokenBlacklistService.blacklistToken(expiredToken, pastExpiry);
        
        // Verify initially blacklisted
        assertTrue(tokenBlacklistService.isBlacklisted(expiredToken), "Token should be initially blacklisted");

        // When
        tokenBlacklistService.shutdown();
        
        // Force an immediate cleanup (should have no effect after shutdown)
        tokenBlacklistService.forceCleanupExpiredTokens();

        // Then
        // The token should still be blacklisted since cleanup tasks are stopped
        assertTrue(tokenBlacklistService.isBlacklisted(expiredToken), "Token should still be blacklisted after shutdown");
    }

    @Test
    void blacklistToken_WithMultipleTokens_ManagesAllTokens() {
        // Given
        String token1 = "token1.jwt";
        String token2 = "token2.jwt";
        long expiry1 = System.currentTimeMillis() + 3600000; // 1 hour from now
        long expiry2 = System.currentTimeMillis() + 7200000; // 2 hours from now

        // When
        tokenBlacklistService.blacklistToken(token1, expiry1);
        tokenBlacklistService.blacklistToken(token2, expiry2);

        // Then
        assertTrue(tokenBlacklistService.isBlacklisted(token1), "First token should be blacklisted");
        assertTrue(tokenBlacklistService.isBlacklisted(token2), "Second token should be blacklisted");
    }

    @Test
    void blacklistToken_WithSameToken_UpdatesExpiry() {
        // Given
        long initialExpiry = System.currentTimeMillis() + 3600000; // 1 hour from now
        long updatedExpiry = System.currentTimeMillis() + 7200000; // 2 hours from now

        // When
        tokenBlacklistService.blacklistToken(testToken, initialExpiry);
        
        // Verify initially blacklisted
        assertTrue(tokenBlacklistService.isBlacklisted(testToken), "Token should be blacklisted with initial expiry");
        
        // Update the expiry
        tokenBlacklistService.blacklistToken(testToken, updatedExpiry);

        // Then
        assertTrue(tokenBlacklistService.isBlacklisted(testToken), "Token should still be blacklisted after expiry update");
    }
    
    @Test
    void isBlacklisted_WithUserToken_ChecksUserBlacklist() {
        // Given
        String userId = "user123";
        String userBlacklistToken = "user_tokens_invalidated:" + userId;
        long expiryTime = System.currentTimeMillis() + 3600000; // 1 hour from now
        
        // When
        tokenBlacklistService.blacklistToken(userBlacklistToken, expiryTime);
        
        // Then
        assertTrue(tokenBlacklistService.isBlacklisted(userBlacklistToken), 
                "User blacklist token should be marked as blacklisted");
    }
    
    @Test
    void isBlacklisted_WithExpiredUserToken_ReturnsFalse() {
        // Given
        String userId = "user123";
        String userBlacklistToken = "user_tokens_invalidated:" + userId;
        long pastExpiry = System.currentTimeMillis() - 60000; // 1 minute ago
        
        // When
        tokenBlacklistService.blacklistToken(userBlacklistToken, pastExpiry);
        tokenBlacklistService.forceCleanupExpiredTokens();
        
        // Then
        assertFalse(tokenBlacklistService.isBlacklisted(userBlacklistToken), 
                "Expired user blacklist token should not be marked as blacklisted after cleanup");
    }
}
