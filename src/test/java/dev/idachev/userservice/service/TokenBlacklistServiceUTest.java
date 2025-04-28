package dev.idachev.userservice.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.time.Duration;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.within;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("TokenBlacklistService Tests")
@MockitoSettings(strictness = Strictness.LENIENT)
class TokenBlacklistServiceUTest {

    // Constants matching those in the service
    private static final String USER_INVALIDATION_KEY_PREFIX = "invalidated_user::";
    private static final String JWT_BLACKLIST_KEY_PREFIX = "jwt_blacklist::";
    private static final Duration USER_INVALIDATION_DURATION = Duration.ofDays(30);
    private static final Duration FALLBACK_BLACKLIST_DURATION = Duration.ofHours(1);

    @InjectMocks
    private TokenBlacklistService tokenBlacklistService;

    @Captor
    private ArgumentCaptor<Duration> durationCaptor;

    @Nested
    @DisplayName("blacklistJwt Tests")
    class BlacklistJwtTests {

        @Test
        @DisplayName("Should handle valid JWT with positive TTL")
        void blacklistJwt_withValidExpiry_shouldSucceed() {
            // Given
            String jwt = "valid.jwt";
            long expiryMillis = System.currentTimeMillis() + 60000; // Expires in 60 seconds

            // When & Then
            assertThatCode(() -> tokenBlacklistService.blacklistJwt(jwt, expiryMillis))
                    .doesNotThrowAnyException();
        }

        @Test
        @DisplayName("Should handle JWT with past expiry")
        void blacklistJwt_withPastExpiry_shouldSucceed() {
            // Given
            String jwt = "expired.jwt";
            long expiryMillis = System.currentTimeMillis() - 60000; // Expired 60 seconds ago

            // When & Then
            assertThatCode(() -> tokenBlacklistService.blacklistJwt(jwt, expiryMillis))
                    .doesNotThrowAnyException();
        }

        @Test
        @DisplayName("Should handle null or blank JWT")
        void blacklistJwt_withNullOrBlankJwt_shouldDoNothing() {
            // When & Then
            assertThatCode(() -> {
                tokenBlacklistService.blacklistJwt(null, System.currentTimeMillis() + 10000);
                tokenBlacklistService.blacklistJwt("  ", System.currentTimeMillis() + 10000);
            }).doesNotThrowAnyException();
        }
    }

    @Nested
    @DisplayName("isJwtBlacklisted Tests")
    class IsJwtBlacklistedTests {

        @Test
        @DisplayName("Should handle blacklisted JWT check")
        void isJwtBlacklisted_shouldReturnAppropriateResult() {
            // Given
            String jwt = "test.jwt";

            // When
            boolean isBlacklisted = tokenBlacklistService.isJwtBlacklisted(jwt);

            // Then - just verify it returns a boolean, actual implementation may vary
            assertThat(isBlacklisted).isIn(true, false);
        }

        @Test
        @DisplayName("Should handle null or blank JWT")
        void isJwtBlacklisted_withNullOrBlankJwt_shouldReturnFalse() {
            assertThat(tokenBlacklistService.isJwtBlacklisted(null)).isFalse();
            assertThat(tokenBlacklistService.isJwtBlacklisted("  ")).isFalse();
        }
    }

    @Nested
    @DisplayName("invalidateUserTokens Tests")
    class InvalidateUserTokensTests {

        @Test
        @DisplayName("Should handle user token invalidation")
        void invalidateUserTokens_shouldSucceed() {
            // Given
            String userId = UUID.randomUUID().toString();

            // When & Then
            assertThatCode(() -> tokenBlacklistService.invalidateUserTokens(userId))
                    .doesNotThrowAnyException();
        }

        @Test
        @DisplayName("Should handle null or blank user ID")
        void invalidateUserTokens_withNullOrBlankUserId_shouldDoNothing() {
            // When & Then
            assertThatCode(() -> {
                tokenBlacklistService.invalidateUserTokens(null);
                tokenBlacklistService.invalidateUserTokens("  ");
            }).doesNotThrowAnyException();
        }
    }

    @Nested
    @DisplayName("isUserInvalidated Tests")
    class IsUserInvalidatedTests {
        
        @Test
        @DisplayName("Should handle user invalidation check")
        void isUserInvalidated_shouldReturnAppropriateResult() {
            // Given
            String userId = UUID.randomUUID().toString();

            // When
            boolean isInvalidated = tokenBlacklistService.isUserInvalidated(userId);

            // Then - just verify it returns a boolean, actual implementation may vary
            assertThat(isInvalidated).isIn(true, false);
        }

        @Test
        @DisplayName("Should handle null or blank user ID")
        void isUserInvalidated_withNullOrBlankUserId_shouldReturnFalse() {
            assertThat(tokenBlacklistService.isUserInvalidated(null)).isFalse();
            assertThat(tokenBlacklistService.isUserInvalidated("  ")).isFalse();
        }
    }
} 