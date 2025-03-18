package dev.idachev.userservice.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Map;
import java.util.concurrent.ScheduledExecutorService;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
public class TokenBlacklistServiceUTest {

    @Mock
    private ScheduledExecutorService scheduler;

    private TokenBlacklistService tokenBlacklistService;

    @BeforeEach
    void setUp() {
        tokenBlacklistService = new TokenBlacklistService(86400000, 100); // 24h expiration, 100 batch size

        ReflectionTestUtils.setField(tokenBlacklistService, "scheduler", scheduler);
    }

    @Test
    void givenValidToken_whenBlacklistToken_thenTokenIsBlacklisted() {

        // Given
        String token = "valid.jwt.token";
        long expiryTime = System.currentTimeMillis() + 3600000; // 1 hour from now

        // When
        tokenBlacklistService.blacklistToken(token, expiryTime);

        // Then
        assertTrue(tokenBlacklistService.isBlacklisted(token));
    }

    @Test
    void givenNullToken_whenBlacklistToken_thenNothingHappens() {

        // When
        tokenBlacklistService.blacklistToken(null, System.currentTimeMillis() + 3600000);

        // Then
        assertFalse(tokenBlacklistService.isBlacklisted(null));
    }

    @Test
    void givenNullExpiryTime_whenBlacklistToken_thenNothingHappens() {

        // When
        tokenBlacklistService.blacklistToken("valid.jwt.token", null);

        // Then
        assertFalse(tokenBlacklistService.isBlacklisted("valid.jwt.token"));
    }

    @Test
    void givenNonBlacklistedToken_whenIsBlacklisted_thenReturnFalse() {

        // Given
        String token = "non.blacklisted.token";

        // When
        boolean result = tokenBlacklistService.isBlacklisted(token);

        // Then
        assertFalse(result);
    }

    @Test
    void givenBlacklistedToken_whenIsBlacklisted_thenReturnTrue() {

        // Given
        String token = "blacklisted.token";
        long expiryTime = System.currentTimeMillis() + 3600000;
        tokenBlacklistService.blacklistToken(token, expiryTime);

        // When
        boolean result = tokenBlacklistService.isBlacklisted(token);

        // Then
        assertTrue(result);
    }


    @Test
    void whenShutdown_thenSchedulerIsStopped() {

        // When
        tokenBlacklistService.shutdown();

        // Then
        verify(scheduler).shutdown();
    }

    @Test
    void givenExpiredTokens_whenCleanupExpiredTokens_thenRemoveExpiredTokens() {

        // Given
        String expiredToken = "expired.token.123";
        String validToken = "valid.token.456";

        long now = System.currentTimeMillis();
        long pastTime = now - 10000; // 10 seconds in the past
        long futureTime = now + 3600000; // 1 hour in the future

        tokenBlacklistService.blacklistToken(expiredToken, pastTime);
        tokenBlacklistService.blacklistToken(validToken, futureTime);

        // Verify initial state - both tokens should be blacklisted
        assertTrue(tokenBlacklistService.isBlacklisted(expiredToken), "Expired token should be blacklisted before cleanup");
        assertTrue(tokenBlacklistService.isBlacklisted(validToken), "Valid token should be blacklisted before cleanup");

        // When
        ReflectionTestUtils.invokeMethod(tokenBlacklistService, "cleanupExpiredTokens");

        // Then
        assertFalse(tokenBlacklistService.isBlacklisted(expiredToken),
                "Expired token should be removed after cleanup");
        assertTrue(tokenBlacklistService.isBlacklisted(validToken),
                "Valid token should still be blacklisted after cleanup");

        @SuppressWarnings("unchecked")
        Map<String, Long> blacklistedTokens = (Map<String, Long>) ReflectionTestUtils.getField(
                tokenBlacklistService, "blacklistedTokens");
        assertEquals(1, blacklistedTokens.size(),
                "Blacklist should contain exactly one token after cleanup");
    }
}
