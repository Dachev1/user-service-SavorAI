package dev.idachev.userservice.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import java.time.Duration;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
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

    @Mock
    private StringRedisTemplate redisTemplate;
    @Mock
    private ValueOperations<String, String> valueOperations; // Mock for opsForValue()

    @InjectMocks
    private TokenBlacklistService tokenBlacklistService;

    @Captor
    private ArgumentCaptor<Duration> durationCaptor;

    @BeforeEach
    void setUp() {
        // When redisTemplate.opsForValue() is called, return our mock ValueOperations
        lenient().when(redisTemplate.opsForValue()).thenReturn(valueOperations);
    }

    @Nested
    @DisplayName("blacklistJwt Tests")
    class BlacklistJwtTests {

        @Test
        @DisplayName("Should set key in Redis with calculated positive TTL")
        void blacklistJwt_withValidExpiry_shouldSetKeyWithCorrectTTL() {
            // Given
            String jwt = "valid.jwt";
            long now = System.currentTimeMillis();
            long expiryMillis = now + 60000; // Expires in 60 seconds
            long expectedTtlMillis = expiryMillis - now;
            String expectedKey = JWT_BLACKLIST_KEY_PREFIX + jwt;

            // When
            tokenBlacklistService.blacklistJwt(jwt, expiryMillis);

            // Then
            verify(valueOperations).set(eq(expectedKey), eq("blacklisted"), durationCaptor.capture());
            // Allow for small difference in calculation vs System.currentTimeMillis()
            assertThat(durationCaptor.getValue().toMillis()).isCloseTo(expectedTtlMillis, within(100L));
        }

        @Test
        @DisplayName("Should set key in Redis with fallback TTL if expiry is in the past")
        void blacklistJwt_withPastExpiry_shouldSetKeyWithFallbackTTL() {
            // Given
            String jwt = "expired.jwt";
            long now = System.currentTimeMillis();
            long expiryMillis = now - 60000; // Expired 60 seconds ago
            String expectedKey = JWT_BLACKLIST_KEY_PREFIX + jwt;

            // When
            tokenBlacklistService.blacklistJwt(jwt, expiryMillis);

            // Then
            verify(valueOperations).set(eq(expectedKey), eq("blacklisted"), eq(FALLBACK_BLACKLIST_DURATION));
        }

        @Test
        @DisplayName("Should not interact with Redis for null or blank JWT")
        void blacklistJwt_withNullOrBlankJwt_shouldDoNothing() {
            tokenBlacklistService.blacklistJwt(null, System.currentTimeMillis() + 10000);
            tokenBlacklistService.blacklistJwt("  ", System.currentTimeMillis() + 10000);
            verifyNoInteractions(valueOperations);
        }

        @Test
        @DisplayName("Should handle Redis exceptions gracefully")
        void blacklistJwt_whenRedisThrows_shouldLogAndNotPropagate() {
            // Given
            String jwt = "valid.jwt";
            long expiryMillis = System.currentTimeMillis() + 60000;
            String expectedKey = JWT_BLACKLIST_KEY_PREFIX + jwt;
            doThrow(new RuntimeException("Redis connection error")).when(valueOperations).set(anyString(), anyString(), any(Duration.class));

            // When & Then (expect no exception propagated)
            assertThatCode(() -> tokenBlacklistService.blacklistJwt(jwt, expiryMillis))
                    .doesNotThrowAnyException();

            // Verify set was attempted
            verify(valueOperations).set(eq(expectedKey), eq("blacklisted"), any(Duration.class));
        }
    }

    @Nested
    @DisplayName("isJwtBlacklisted Tests")
    class IsJwtBlacklistedTests {

        @Test
        @DisplayName("Should return true if Redis has the key")
        void isJwtBlacklisted_whenKeyExists_shouldReturnTrue() {
            // Given
            String jwt = "blacklisted.jwt";
            String expectedKey = JWT_BLACKLIST_KEY_PREFIX + jwt;
            when(redisTemplate.hasKey(expectedKey)).thenReturn(true);

            // When
            boolean isBlacklisted = tokenBlacklistService.isJwtBlacklisted(jwt);

            // Then
            assertThat(isBlacklisted).isTrue();
            verify(redisTemplate).hasKey(expectedKey);
        }

        @Test
        @DisplayName("Should return false if Redis does not have the key")
        void isJwtBlacklisted_whenKeyDoesNotExist_shouldReturnFalse() {
            // Given
            String jwt = "not.blacklisted.jwt";
            String expectedKey = JWT_BLACKLIST_KEY_PREFIX + jwt;
            when(redisTemplate.hasKey(expectedKey)).thenReturn(false);

             // When
            boolean isBlacklisted = tokenBlacklistService.isJwtBlacklisted(jwt);

            // Then
            assertThat(isBlacklisted).isFalse();
            verify(redisTemplate).hasKey(expectedKey);
        }

        @Test
        @DisplayName("Should return false for null or blank JWT")
        void isJwtBlacklisted_withNullOrBlankJwt_shouldReturnFalse() {
             assertThat(tokenBlacklistService.isJwtBlacklisted(null)).isFalse();
             assertThat(tokenBlacklistService.isJwtBlacklisted("  ")).isFalse();
             verifyNoInteractions(redisTemplate);
        }

        @Test
        @DisplayName("Should return false if Redis check fails")
        void isJwtBlacklisted_whenRedisThrows_shouldReturnFalse() {
            // Given
            String jwt = "error.jwt";
            String expectedKey = JWT_BLACKLIST_KEY_PREFIX + jwt;
            when(redisTemplate.hasKey(expectedKey)).thenThrow(new RuntimeException("Redis down"));

            // When
            boolean isBlacklisted = tokenBlacklistService.isJwtBlacklisted(jwt);

            // Then
            assertThat(isBlacklisted).isFalse(); // Fails safe to false
            verify(redisTemplate).hasKey(expectedKey);
        }
    }

     @Nested
    @DisplayName("invalidateUserTokens Tests")
    class InvalidateUserTokensTests {

        @Test
        @DisplayName("Should set user invalidation key in Redis with fixed duration")
        void invalidateUserTokens_shouldSetKeyWithFixedTTL() {
            // Given
            String userId = UUID.randomUUID().toString();
            String expectedKey = USER_INVALIDATION_KEY_PREFIX + userId;

            // When
            tokenBlacklistService.invalidateUserTokens(userId);

            // Then
            verify(valueOperations).set(eq(expectedKey), eq("invalidated"), eq(USER_INVALIDATION_DURATION));
        }

         @Test
        @DisplayName("Should not interact with Redis for null or blank user ID")
        void invalidateUserTokens_withNullOrBlankUserId_shouldDoNothing() {
             tokenBlacklistService.invalidateUserTokens(null);
             tokenBlacklistService.invalidateUserTokens("  ");
             verifyNoInteractions(valueOperations);
        }

         @Test
        @DisplayName("Should handle Redis exceptions gracefully")
        void invalidateUserTokens_whenRedisThrows_shouldLogAndNotPropagate() {
            // Given
             String userId = UUID.randomUUID().toString();
             String expectedKey = USER_INVALIDATION_KEY_PREFIX + userId;
             doThrow(new RuntimeException("Redis error")).when(valueOperations).set(anyString(), anyString(), any(Duration.class));

            // When & Then
             assertThatCode(() -> tokenBlacklistService.invalidateUserTokens(userId))
                    .doesNotThrowAnyException();

             verify(valueOperations).set(eq(expectedKey), eq("invalidated"), eq(USER_INVALIDATION_DURATION));
        }
    }

     @Nested
    @DisplayName("isUserInvalidated Tests")
    class IsUserInvalidatedTests {
        @Test
        @DisplayName("Should return true if Redis has the user invalidation key")
        void isUserInvalidated_whenKeyExists_shouldReturnTrue() {
            // Given
            String userId = UUID.randomUUID().toString();
            String expectedKey = USER_INVALIDATION_KEY_PREFIX + userId;
            when(redisTemplate.hasKey(expectedKey)).thenReturn(true);

             // When
            boolean isInvalidated = tokenBlacklistService.isUserInvalidated(userId);

            // Then
            assertThat(isInvalidated).isTrue();
            verify(redisTemplate).hasKey(expectedKey);
        }

         @Test
        @DisplayName("Should return false if Redis does not have the key")
        void isUserInvalidated_whenKeyDoesNotExist_shouldReturnFalse() {
             // Given
            String userId = UUID.randomUUID().toString();
            String expectedKey = USER_INVALIDATION_KEY_PREFIX + userId;
            when(redisTemplate.hasKey(expectedKey)).thenReturn(false);

            // When
            boolean isInvalidated = tokenBlacklistService.isUserInvalidated(userId);

            // Then
            assertThat(isInvalidated).isFalse();
            verify(redisTemplate).hasKey(expectedKey);
        }

         @Test
        @DisplayName("Should return false for null or blank user ID")
        void isUserInvalidated_withNullOrBlankUserId_shouldReturnFalse() {
            assertThat(tokenBlacklistService.isUserInvalidated(null)).isFalse();
            assertThat(tokenBlacklistService.isUserInvalidated("  ")).isFalse();
            verifyNoInteractions(redisTemplate);
        }

         @Test
        @DisplayName("Should return false if Redis check fails")
        void isUserInvalidated_whenRedisThrows_shouldReturnFalse() {
             // Given
            String userId = UUID.randomUUID().toString();
            String expectedKey = USER_INVALIDATION_KEY_PREFIX + userId;
            when(redisTemplate.hasKey(expectedKey)).thenThrow(new RuntimeException("Redis down"));

            // When
            boolean isInvalidated = tokenBlacklistService.isUserInvalidated(userId);

            // Then
            assertThat(isInvalidated).isFalse(); // Fails safe to false
            verify(redisTemplate).hasKey(expectedKey);
        }
    }
} 