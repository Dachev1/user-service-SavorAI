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
        long tokenExpirationMs = 3600000L; // 1 hour
        long cleanupBatchSize = 100L;

        // Directly create service with actual values
        tokenBlacklistService = new TokenBlacklistService(tokenExpirationMs, cleanupBatchSize);

        testToken = "test.jwt.token";
        testExpiryTime = System.currentTimeMillis() + 3600000; // 1 hour from now
    }

    @Test
    void blacklistToken_WithValidTokenAndExpiry_AddsToBlacklist() {
        // When
        tokenBlacklistService.blacklistToken(testToken, testExpiryTime);

        // Then
        assertTrue(tokenBlacklistService.isBlacklisted(testToken));
    }

    @Test
    void blacklistToken_WithNullToken_DoesNotAddToBlacklist() {
        // When
        tokenBlacklistService.blacklistToken(null, testExpiryTime);

        // Then
        assertFalse(tokenBlacklistService.isBlacklisted(null));
    }

    @Test
    void blacklistToken_WithNullExpiry_DoesNotAddToBlacklist() {
        // When
        tokenBlacklistService.blacklistToken(testToken, null);

        // Then
        assertFalse(tokenBlacklistService.isBlacklisted(testToken));
    }

    @Test
    void isBlacklisted_WithBlacklistedToken_ReturnsTrue() {
        // Given
        tokenBlacklistService.blacklistToken(testToken, testExpiryTime);

        // When/Then
        assertTrue(tokenBlacklistService.isBlacklisted(testToken));
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
    void cleanupExpiredTokens_RemovesExpiredTokens() {
        // Given
        String expiredToken = "expired.token";
        long expiredTime = System.currentTimeMillis() - 1000; // 1 second ago
        tokenBlacklistService.blacklistToken(expiredToken, expiredTime);
        tokenBlacklistService.blacklistToken(testToken, testExpiryTime);

        // When
        // Directly force cleanup instead of waiting for scheduled task
        tokenBlacklistService.forceCleanupExpiredTokens();

        // Then
        assertFalse(tokenBlacklistService.isBlacklisted(expiredToken));
        assertTrue(tokenBlacklistService.isBlacklisted(testToken));
    }

    @Test
    void shutdown_StopsCleanupTask() throws InterruptedException {
        // Given
        String expiredToken = "expired.token";
        long expiredTime = System.currentTimeMillis() - 1000; // 1 second ago
        tokenBlacklistService.blacklistToken(expiredToken, expiredTime);

        // When
        tokenBlacklistService.shutdown();

        // Then
        // Wait to ensure cleanup task is stopped
        Thread.sleep(2000);
        assertTrue(tokenBlacklistService.isBlacklisted(expiredToken));
    }

    @Test
    void blacklistToken_WithMultipleTokens_ManagesAllTokens() {
        // Given
        String token1 = "token1";
        String token2 = "token2";
        long expiry1 = System.currentTimeMillis() + 3600000;
        long expiry2 = System.currentTimeMillis() + 7200000;

        // When
        tokenBlacklistService.blacklistToken(token1, expiry1);
        tokenBlacklistService.blacklistToken(token2, expiry2);

        // Then
        assertTrue(tokenBlacklistService.isBlacklisted(token1));
        assertTrue(tokenBlacklistService.isBlacklisted(token2));
    }

    @Test
    void blacklistToken_WithSameToken_UpdatesExpiry() {
        // Given
        long initialExpiry = System.currentTimeMillis() + 3600000;
        long updatedExpiry = System.currentTimeMillis() + 7200000;

        // When
        tokenBlacklistService.blacklistToken(testToken, initialExpiry);
        tokenBlacklistService.blacklistToken(testToken, updatedExpiry);

        // Then
        assertTrue(tokenBlacklistService.isBlacklisted(testToken));
    }
}
