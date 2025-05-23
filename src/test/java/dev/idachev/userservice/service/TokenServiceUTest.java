package dev.idachev.userservice.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.security.core.userdetails.UserDetails;

import dev.idachev.userservice.config.JwtConfig;
import dev.idachev.userservice.exception.AuthenticationException;
import dev.idachev.userservice.exception.InvalidTokenException;
import dev.idachev.userservice.model.User;
import dev.idachev.userservice.security.UserPrincipal;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;

/**
 * Unit tests for {@link TokenService}.
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("TokenService Tests")
@MockitoSettings(strictness = Strictness.LENIENT) // Lenient to avoid UnnecessaryStubbingException for unused mocks in
                                                  // simple tests
class TokenServiceUTest {

    @Mock
    private JwtConfig jwtConfig;
    @Mock
    private TokenBlacklistService tokenBlacklistService;

    @InjectMocks
    private TokenService tokenService;

    private UserDetails userDetails;
    private final String TEST_TOKEN_RAW = "raw.jwt.token";
    private final String TEST_TOKEN_BEARER = "Bearer " + TEST_TOKEN_RAW;
    private final String TEST_USERNAME = "testuser";
    private final UUID TEST_USER_ID = UUID.randomUUID();
    private final Date TEST_EXPIRATION = new Date(System.currentTimeMillis() + 100000);

    @BeforeEach
    void setUp() {
        User user = User.builder().id(TEST_USER_ID).username(TEST_USERNAME).build();
        userDetails = new UserPrincipal(user);
    }

    @Nested
    @DisplayName("generateToken Tests")
    class GenerateTokenTests {

        @Test
        @DisplayName("Should return token generated by JwtConfig")
        void generateToken_shouldReturnTokenFromJwtConfig() {
            when(jwtConfig.generateToken(userDetails)).thenReturn(TEST_TOKEN_RAW);
            String generatedToken = tokenService.generateToken(userDetails);
            assertThat(generatedToken).isEqualTo(TEST_TOKEN_RAW);
            verify(jwtConfig).generateToken(userDetails);
            verifyNoMoreInteractions(jwtConfig);
            verifyNoInteractions(tokenBlacklistService);
        }

        @Test
        @DisplayName("Should return empty string if UserDetails is null")
        void generateToken_withNullUserDetails_shouldReturnEmptyString() {
            String generatedToken = tokenService.generateToken(null);
            assertThat(generatedToken).isEmpty();
            verifyNoInteractions(jwtConfig, tokenBlacklistService);
        }

        @Test
        @DisplayName("Should return empty string if JwtConfig throws exception")
        void generateToken_whenJwtConfigThrowsException_shouldReturnEmptyString() {
            when(jwtConfig.generateToken(userDetails)).thenThrow(new RuntimeException("Config error"));
            String generatedToken = tokenService.generateToken(userDetails);
            assertThat(generatedToken).isEmpty();
            verify(jwtConfig).generateToken(userDetails);
            verifyNoMoreInteractions(jwtConfig);
            verifyNoInteractions(tokenBlacklistService);
        }

        @Test
        @DisplayName("Should return empty string if JwtConfig returns null")
        void generateToken_whenJwtConfigReturnsNull_shouldReturnEmptyString() {
            when(jwtConfig.generateToken(userDetails)).thenReturn(null);
            String generatedToken = tokenService.generateToken(userDetails);
            assertThat(generatedToken).isEmpty();
            verify(jwtConfig).generateToken(userDetails);
            verifyNoMoreInteractions(jwtConfig);
            verifyNoInteractions(tokenBlacklistService);
        }
    }

    @Nested
    @DisplayName("extractClaim Tests (UserId, Username, Expiration)")
    class ExtractClaimTests {

        @Test
        @DisplayName("extractUserId should return UUID from JwtConfig")
        void extractUserId_shouldReturnUUIDFromJwtConfig() {
            when(jwtConfig.extractUserId(TEST_TOKEN_RAW)).thenReturn(TEST_USER_ID);
            UUID extractedId = tokenService.extractUserId(TEST_TOKEN_BEARER);
            assertThat(extractedId).isEqualTo(TEST_USER_ID);
            verify(jwtConfig).extractUserId(TEST_TOKEN_RAW);
            verifyNoMoreInteractions(jwtConfig);
            verifyNoInteractions(tokenBlacklistService);
        }

        @Test
        @DisplayName("extractUsername should return String from JwtConfig")
        void extractUsername_shouldReturnStringFromJwtConfig() {
            when(jwtConfig.extractUsername(TEST_TOKEN_RAW)).thenReturn(TEST_USERNAME);
            String extractedUsername = tokenService.extractUsername(TEST_TOKEN_RAW);
            assertThat(extractedUsername).isEqualTo(TEST_USERNAME);
            verify(jwtConfig).extractUsername(TEST_TOKEN_RAW);
            verifyNoMoreInteractions(jwtConfig);
            verifyNoInteractions(tokenBlacklistService);
        }

        @Test
        @DisplayName("extractExpiration should return Date from JwtConfig")
        void extractExpiration_shouldReturnDateFromJwtConfig() {
            when(jwtConfig.extractExpiration(TEST_TOKEN_RAW)).thenReturn(TEST_EXPIRATION);
            Date extractedExpiration = tokenService.extractExpiration(TEST_TOKEN_BEARER);
            assertThat(extractedExpiration).isEqualTo(TEST_EXPIRATION);
            verify(jwtConfig).extractExpiration(TEST_TOKEN_RAW);
            verifyNoMoreInteractions(jwtConfig);
            verifyNoInteractions(tokenBlacklistService);
        }

        @Test
        @DisplayName("extractClaim should throw InvalidTokenException if JwtConfig throws non-ExpiredJwtException")
        void extractClaim_whenJwtConfigThrowsNonExpiredJwtException_shouldThrowInvalidTokenException() {
            when(jwtConfig.extractUserId(TEST_TOKEN_RAW)).thenThrow(new JwtException("Bad signature"));

            assertThatThrownBy(() -> tokenService.extractUserId(TEST_TOKEN_BEARER))
                    .isInstanceOf(InvalidTokenException.class)
                    .hasMessageContaining("Invalid token format while extracting user ID")
                    .hasCauseInstanceOf(JwtException.class);

            verify(jwtConfig).extractUserId(TEST_TOKEN_RAW);
            verifyNoMoreInteractions(jwtConfig);
            verifyNoInteractions(tokenBlacklistService);
        }

        @Test
        @DisplayName("extractClaim should re-throw ExpiredJwtException if JwtConfig throws it")
        void extractClaim_whenJwtConfigThrowsExpiredJwtException_shouldReThrow() {
            ExpiredJwtException expiredException = new ExpiredJwtException(null, null, "Token expired");
            when(jwtConfig.extractUserId(TEST_TOKEN_RAW)).thenThrow(expiredException);

            assertThatThrownBy(() -> tokenService.extractUserId(TEST_TOKEN_BEARER))
                    .isInstanceOf(ExpiredJwtException.class)
                    .isEqualTo(expiredException);

            verify(jwtConfig).extractUserId(TEST_TOKEN_RAW);
            verifyNoMoreInteractions(jwtConfig);
            verifyNoInteractions(tokenBlacklistService);
        }

        @Test
        @DisplayName("extractClaim should throw InvalidTokenException for null or blank token")
        void extractClaim_withNullOrBlankToken_shouldThrowInvalidTokenException() {
            assertThatThrownBy(() -> tokenService.extractUserId(null))
                    .isInstanceOf(InvalidTokenException.class)
                    .hasMessageContaining("Token cannot be null or blank");

            assertThatThrownBy(() -> tokenService.extractUsername(""))
                    .isInstanceOf(InvalidTokenException.class)
                    .hasMessageContaining("Token cannot be null or blank");

            assertThatThrownBy(() -> tokenService.extractExpiration("   "))
                    .isInstanceOf(InvalidTokenException.class)
                    .hasMessageContaining("Token cannot be null or blank");

            verifyNoInteractions(jwtConfig, tokenBlacklistService);
        }
    }

    @Nested
    @DisplayName("validateToken Tests")
    class ValidateTokenTests {

        @Test
        @DisplayName("Should return true for valid, non-blacklisted, non-invalidated token")
        void validateToken_validNonBlacklistedNonInvalidated_shouldReturnTrue() {
            when(tokenBlacklistService.isJwtBlacklisted(TEST_TOKEN_RAW)).thenReturn(false);
            when(tokenBlacklistService.isUserInvalidated(TEST_USER_ID.toString())).thenReturn(false);
            when(jwtConfig.validateToken(TEST_TOKEN_RAW, userDetails)).thenReturn(true);

            boolean isValid = tokenService.validateToken(TEST_TOKEN_BEARER, userDetails);

            assertThat(isValid).isTrue();
            verify(tokenBlacklistService).isJwtBlacklisted(TEST_TOKEN_RAW);
            verify(tokenBlacklistService).isUserInvalidated(TEST_USER_ID.toString());
            verify(jwtConfig).validateToken(TEST_TOKEN_RAW, userDetails);
            verifyNoMoreInteractions(tokenBlacklistService, jwtConfig);
        }

        @Test
        @DisplayName("Should return false if token is blacklisted")
        void validateToken_whenTokenBlacklisted_shouldReturnFalse() {
            when(tokenBlacklistService.isJwtBlacklisted(TEST_TOKEN_RAW)).thenReturn(true);
            boolean isValid = tokenService.validateToken(TEST_TOKEN_BEARER, userDetails);
            assertThat(isValid).isFalse();
            verify(tokenBlacklistService).isJwtBlacklisted(TEST_TOKEN_RAW);
            verifyNoMoreInteractions(tokenBlacklistService);
            verifyNoInteractions(jwtConfig);
        }

        @Test
        @DisplayName("Should return false if user is invalidated")
        void validateToken_whenUserInvalidated_shouldReturnFalse() {
            when(tokenBlacklistService.isJwtBlacklisted(TEST_TOKEN_RAW)).thenReturn(false);
            when(tokenBlacklistService.isUserInvalidated(TEST_USER_ID.toString())).thenReturn(true);
            boolean isValid = tokenService.validateToken(TEST_TOKEN_BEARER, userDetails);
            assertThat(isValid).isFalse();
            verify(tokenBlacklistService).isJwtBlacklisted(TEST_TOKEN_RAW);
            verify(tokenBlacklistService).isUserInvalidated(TEST_USER_ID.toString());
            verifyNoMoreInteractions(tokenBlacklistService);
            verifyNoInteractions(jwtConfig);
        }

        @Test
        @DisplayName("Should return false if JwtConfig validation fails")
        void validateToken_whenJwtConfigValidationFails_shouldReturnFalse() {
            when(tokenBlacklistService.isJwtBlacklisted(TEST_TOKEN_RAW)).thenReturn(false);
            when(tokenBlacklistService.isUserInvalidated(TEST_USER_ID.toString())).thenReturn(false);
            when(jwtConfig.validateToken(TEST_TOKEN_RAW, userDetails)).thenReturn(false);

            boolean isValid = tokenService.validateToken(TEST_TOKEN_BEARER, userDetails);

            assertThat(isValid).isFalse();
            verify(tokenBlacklistService).isJwtBlacklisted(TEST_TOKEN_RAW);
            verify(tokenBlacklistService).isUserInvalidated(TEST_USER_ID.toString());
            verify(jwtConfig).validateToken(TEST_TOKEN_RAW, userDetails);
            verifyNoMoreInteractions(tokenBlacklistService, jwtConfig);
        }

        @Test
        @DisplayName("Should handle UserDetails that are not UserPrincipal")
        void validateToken_withNonUserPrincipal_shouldSkipUserInvalidationCheck() {
            UserDetails nonPrincipalDetails = mock(UserDetails.class);
            when(tokenBlacklistService.isJwtBlacklisted(TEST_TOKEN_RAW)).thenReturn(false);
            when(jwtConfig.validateToken(TEST_TOKEN_RAW, nonPrincipalDetails)).thenReturn(true);

            boolean isValid = tokenService.validateToken(TEST_TOKEN_BEARER, nonPrincipalDetails);

            assertThat(isValid).isTrue();
            verify(tokenBlacklistService).isJwtBlacklisted(TEST_TOKEN_RAW);
            verify(tokenBlacklistService, never()).isUserInvalidated(anyString());
            verify(jwtConfig).validateToken(TEST_TOKEN_RAW, nonPrincipalDetails);
            verifyNoMoreInteractions(tokenBlacklistService, jwtConfig);
        }
    }

    @Nested
    @DisplayName("blacklistToken Tests")
    class BlacklistTokenTests {

        @Test
        @DisplayName("Should call blacklist service with correct token and expiry time")
        void blacklistToken_shouldCallBlacklistServiceWithExpiry() {
            doNothing().when(tokenBlacklistService).blacklistJwt(TEST_TOKEN_RAW, TEST_EXPIRATION.getTime());

            tokenService.blacklistToken(TEST_TOKEN_BEARER, TEST_EXPIRATION);

            verify(tokenBlacklistService).blacklistJwt(TEST_TOKEN_RAW, TEST_EXPIRATION.getTime());
            verifyNoMoreInteractions(tokenBlacklistService);
            verifyNoInteractions(jwtConfig);
        }

        @Test
        @DisplayName("Should throw IllegalArgumentException for null or empty token")
        void blacklistToken_withNullOrEmptyToken_shouldThrowIllegalArgumentException() {
            assertThatThrownBy(() -> tokenService.blacklistToken(null, TEST_EXPIRATION))
                    .isInstanceOf(IllegalArgumentException.class);
            assertThatThrownBy(() -> tokenService.blacklistToken("", TEST_EXPIRATION))
                    .isInstanceOf(IllegalArgumentException.class);
            verifyNoInteractions(jwtConfig, tokenBlacklistService);
        }

        @Test
        @DisplayName("Should not propagate exceptions from blacklist service")
        void blacklistToken_whenBlacklistServiceThrows_shouldNotPropagate() {
            String jwt = "error.jwt";
            Date expiry = new Date();
            doThrow(new RuntimeException("Redis error")).when(tokenBlacklistService).blacklistJwt(jwt,
                    expiry.getTime());

            assertThatCode(() -> tokenService.blacklistToken(jwt, expiry))
                    .doesNotThrowAnyException();

            verify(tokenBlacklistService).blacklistJwt(jwt, expiry.getTime());
            verifyNoMoreInteractions(tokenBlacklistService);
            verifyNoInteractions(jwtConfig);
        }
    }

    @Nested
    @DisplayName("isJwtBlacklisted Tests")
    class IsJwtBlacklistedTests {
        @Test
        @DisplayName("Should return true when blacklist service returns true")
        void isJwtBlacklisted_whenBlacklisted_shouldReturnTrue() {
            when(tokenBlacklistService.isJwtBlacklisted(TEST_TOKEN_RAW)).thenReturn(true);
            assertThat(tokenService.isJwtBlacklisted(TEST_TOKEN_BEARER)).isTrue();
            verify(tokenBlacklistService).isJwtBlacklisted(TEST_TOKEN_RAW);
            verifyNoMoreInteractions(tokenBlacklistService);
        }

        @Test
        @DisplayName("Should return false when blacklist service returns false")
        void isJwtBlacklisted_whenNotBlacklisted_shouldReturnFalse() {
            when(tokenBlacklistService.isJwtBlacklisted(TEST_TOKEN_RAW)).thenReturn(false);
            assertThat(tokenService.isJwtBlacklisted(TEST_TOKEN_RAW)).isFalse();
            verify(tokenBlacklistService).isJwtBlacklisted(TEST_TOKEN_RAW);
            verifyNoMoreInteractions(tokenBlacklistService);
        }

        @Test
        @DisplayName("Should return false for null or empty token")
        void isJwtBlacklisted_withNullOrEmpty_shouldReturnFalse() {
            assertThat(tokenService.isJwtBlacklisted(null)).isFalse();
            assertThat(tokenService.isJwtBlacklisted("")).isFalse();
            verifyNoInteractions(tokenBlacklistService);
        }
    }

    @Nested
    @DisplayName("isUserInvalidated Tests")
    class IsUserInvalidatedTests {
        @Test
        @DisplayName("Should return true when blacklist service returns true")
        void isUserInvalidated_whenInvalidated_shouldReturnTrue() {
            when(tokenBlacklistService.isUserInvalidated(TEST_USER_ID.toString())).thenReturn(true);
            assertThat(tokenService.isUserInvalidated(TEST_USER_ID)).isTrue();
            verify(tokenBlacklistService).isUserInvalidated(TEST_USER_ID.toString());
            verifyNoMoreInteractions(tokenBlacklistService);
        }

        @Test
        @DisplayName("Should return false when blacklist service returns false")
        void isUserInvalidated_whenNotInvalidated_shouldReturnFalse() {
            when(tokenBlacklistService.isUserInvalidated(TEST_USER_ID.toString())).thenReturn(false);
            assertThat(tokenService.isUserInvalidated(TEST_USER_ID)).isFalse();
            verify(tokenBlacklistService).isUserInvalidated(TEST_USER_ID.toString());
            verifyNoMoreInteractions(tokenBlacklistService);
        }

        @Test
        @DisplayName("Should return false for null user ID")
        void isUserInvalidated_withNullUserId_shouldReturnFalse() {
            assertThat(tokenService.isUserInvalidated(null)).isFalse();
            verifyNoInteractions(tokenBlacklistService);
        }
    }

    @Nested
    @DisplayName("invalidateUserTokens Tests")
    class InvalidateUserTokensTests {
        @Test
        @DisplayName("Should call blacklist service with user ID string")
        void invalidateUserTokens_shouldCallBlacklistService() {
            doNothing().when(tokenBlacklistService).invalidateUserTokens(TEST_USER_ID.toString());
            tokenService.invalidateUserTokens(TEST_USER_ID);
            verify(tokenBlacklistService).invalidateUserTokens(TEST_USER_ID.toString());
            verifyNoMoreInteractions(tokenBlacklistService);
        }

        @Test
        @DisplayName("Should throw IllegalArgumentException for null user ID")
        void invalidateUserTokens_withNullUserId_shouldThrowIllegalArgumentException() {
            assertThatThrownBy(() -> tokenService.invalidateUserTokens(null))
                    .isInstanceOf(IllegalArgumentException.class);
            verifyNoInteractions(tokenBlacklistService);
        }

        @Test
        @DisplayName("Should wrap and throw exception from blacklist service")
        void invalidateUserTokens_whenBlacklistServiceThrows_shouldWrapAndThrow() {
            RuntimeException cause = new RuntimeException("Redis error");
            doThrow(cause).when(tokenBlacklistService).invalidateUserTokens(TEST_USER_ID.toString());

            assertThatThrownBy(() -> tokenService.invalidateUserTokens(TEST_USER_ID))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessageContaining("Failed to signal token invalidation for user " + TEST_USER_ID)
                    .hasCause(cause);

            verify(tokenBlacklistService).invalidateUserTokens(TEST_USER_ID.toString());
            verifyNoMoreInteractions(tokenBlacklistService);
        }
    }

    @Nested
    @DisplayName("refreshToken Tests")
    class RefreshTokenTests {

        private final String OLD_REFRESH_TOKEN = "old.refreshable.token";
        private final String OLD_REFRESH_HEADER = "Bearer " + OLD_REFRESH_TOKEN;
        private final UUID REFRESH_USER_ID = UUID.randomUUID();
        private User refreshUser;
        private UserDetails refreshUserDetails;

        @BeforeEach
        void setupRefreshUser() {
            refreshUser = User.builder()
                    .id(REFRESH_USER_ID)
                    .username("refresher")
                    .enabled(true)
                    .banned(false)
                    .build();
            refreshUserDetails = new UserPrincipal(refreshUser);
        }

        @Test
        @DisplayName("Should refresh token successfully for valid user and token")
        void refreshToken_validUserAndToken_shouldBlacklistOldAndReturnNew() {
            String newGeneratedToken = "new.refreshed.token";
            // Use a fixed expiry for predictability
            Date expiryDate = Date.from(new Date().toInstant().plus(1, ChronoUnit.HOURS));

            when(tokenBlacklistService.isJwtBlacklisted(OLD_REFRESH_TOKEN)).thenReturn(false);
            when(jwtConfig.extractUserId(OLD_REFRESH_TOKEN)).thenReturn(REFRESH_USER_ID);
            when(tokenBlacklistService.isUserInvalidated(REFRESH_USER_ID.toString())).thenReturn(false);
            when(jwtConfig.extractExpiration(OLD_REFRESH_TOKEN)).thenReturn(expiryDate);
            doNothing().when(tokenBlacklistService).blacklistJwt(OLD_REFRESH_TOKEN, expiryDate.getTime());
            when(jwtConfig.generateToken(refreshUserDetails)).thenReturn(newGeneratedToken);

            String resultToken = tokenService.refreshToken(OLD_REFRESH_HEADER, refreshUserDetails);

            assertThat(resultToken).isEqualTo(newGeneratedToken);

            verify(tokenBlacklistService).isJwtBlacklisted(OLD_REFRESH_TOKEN);
            verify(jwtConfig).extractUserId(OLD_REFRESH_TOKEN);
            verify(tokenBlacklistService).isUserInvalidated(REFRESH_USER_ID.toString());
            verify(jwtConfig).extractExpiration(OLD_REFRESH_TOKEN);
            verify(tokenBlacklistService).blacklistJwt(OLD_REFRESH_TOKEN, expiryDate.getTime());
            verify(jwtConfig).generateToken(refreshUserDetails);
            verifyNoMoreInteractions(tokenBlacklistService, jwtConfig);
        }

        @Test
        @DisplayName("Should throw AuthenticationException if token is already blacklisted")
        void refreshToken_whenOldTokenBlacklisted_shouldThrowAuthenticationException() {
            when(tokenBlacklistService.isJwtBlacklisted(OLD_REFRESH_TOKEN)).thenReturn(true);

            assertThatThrownBy(() -> tokenService.refreshToken(OLD_REFRESH_HEADER, refreshUserDetails))
                    .isInstanceOf(AuthenticationException.class)
                    .hasMessageContaining("Token is blacklisted"); // Check specific message

            verify(tokenBlacklistService).isJwtBlacklisted(OLD_REFRESH_TOKEN);
            verifyNoMoreInteractions(tokenBlacklistService);
            verifyNoInteractions(jwtConfig);
        }

        @Test
        @DisplayName("Should throw AuthenticationException if user is invalidated")
        void refreshToken_whenUserInvalidated_shouldThrowAuthenticationException() {
            when(tokenBlacklistService.isJwtBlacklisted(OLD_REFRESH_TOKEN)).thenReturn(false);
            when(jwtConfig.extractUserId(OLD_REFRESH_TOKEN)).thenReturn(REFRESH_USER_ID);
            when(tokenBlacklistService.isUserInvalidated(REFRESH_USER_ID.toString())).thenReturn(true);

            assertThatThrownBy(() -> tokenService.refreshToken(OLD_REFRESH_HEADER, refreshUserDetails))
                    .isInstanceOf(AuthenticationException.class)
                    .hasMessageContaining("User session invalidated"); // Check specific message

            verify(tokenBlacklistService).isJwtBlacklisted(OLD_REFRESH_TOKEN);
            verify(jwtConfig).extractUserId(OLD_REFRESH_TOKEN);
            verify(tokenBlacklistService).isUserInvalidated(REFRESH_USER_ID.toString());
            verifyNoMoreInteractions(tokenBlacklistService, jwtConfig);
        }

        @Test
        @DisplayName("Should throw AuthenticationException if user is banned")
        void refreshToken_whenUserIsBanned_shouldBlacklistTokenAndThrow() {
            refreshUser = refreshUser.toBuilder().banned(true).build();
            refreshUserDetails = new UserPrincipal(refreshUser);
            Date expiryDate = Date.from(new Date().toInstant().plus(1, ChronoUnit.HOURS));

            when(tokenBlacklistService.isJwtBlacklisted(OLD_REFRESH_TOKEN)).thenReturn(false);
            when(jwtConfig.extractUserId(OLD_REFRESH_TOKEN)).thenReturn(REFRESH_USER_ID);
            when(tokenBlacklistService.isUserInvalidated(REFRESH_USER_ID.toString())).thenReturn(false);
            when(jwtConfig.extractExpiration(OLD_REFRESH_TOKEN)).thenReturn(expiryDate);
            doNothing().when(tokenBlacklistService).blacklistJwt(OLD_REFRESH_TOKEN, expiryDate.getTime());

            assertThatThrownBy(() -> tokenService.refreshToken(OLD_REFRESH_HEADER, refreshUserDetails))
                    .isInstanceOf(AuthenticationException.class)
                    .hasMessageContaining("User is banned"); // Check specific message

            // Verify the specific interactions that should happen before throwing
            verify(tokenBlacklistService).isJwtBlacklisted(OLD_REFRESH_TOKEN);
            verify(jwtConfig).extractUserId(OLD_REFRESH_TOKEN);
            verify(tokenBlacklistService).isUserInvalidated(REFRESH_USER_ID.toString());
            verify(jwtConfig).extractExpiration(OLD_REFRESH_TOKEN);
            verify(tokenBlacklistService).blacklistJwt(OLD_REFRESH_TOKEN, expiryDate.getTime());
            verify(jwtConfig, never()).generateToken(any());
        }

        @Test
        @DisplayName("Should throw AuthenticationException if token user ID mismatches UserDetails ID")
        void refreshToken_whenUserIdMismatch_shouldThrowAuthenticationException() {
            UUID differentUserId = UUID.randomUUID();
            User differentUser = User.builder().id(differentUserId).build();
            UserDetails differentUserDetails = new UserPrincipal(differentUser);

            when(tokenBlacklistService.isJwtBlacklisted(OLD_REFRESH_TOKEN)).thenReturn(false);
            when(jwtConfig.extractUserId(OLD_REFRESH_TOKEN)).thenReturn(REFRESH_USER_ID);
            when(tokenBlacklistService.isUserInvalidated(REFRESH_USER_ID.toString())).thenReturn(false);

            assertThatThrownBy(() -> tokenService.refreshToken(OLD_REFRESH_HEADER, differentUserDetails))
                    .isInstanceOf(AuthenticationException.class)
                    .hasMessageContaining("User mismatch"); // Check specific message

            verify(tokenBlacklistService).isJwtBlacklisted(OLD_REFRESH_TOKEN);
            verify(jwtConfig).extractUserId(OLD_REFRESH_TOKEN);
            verify(tokenBlacklistService).isUserInvalidated(REFRESH_USER_ID.toString());
        }

        @Test
        @DisplayName("Should throw AuthenticationException if UserDetails not UserPrincipal")
        void refreshToken_withNonUserPrincipal_shouldThrowAuthenticationException() {
            UserDetails nonPrincipalDetails = mock(UserDetails.class);

            when(tokenBlacklistService.isJwtBlacklisted(OLD_REFRESH_TOKEN)).thenReturn(false);
            when(jwtConfig.extractUserId(OLD_REFRESH_TOKEN)).thenReturn(REFRESH_USER_ID);
            when(tokenBlacklistService.isUserInvalidated(REFRESH_USER_ID.toString())).thenReturn(false);

            assertThatThrownBy(() -> tokenService.refreshToken(OLD_REFRESH_HEADER, nonPrincipalDetails))
                    .isInstanceOf(AuthenticationException.class)
                    .hasMessageContaining("Invalid user principal type"); // Check specific message

            verify(tokenBlacklistService).isJwtBlacklisted(OLD_REFRESH_TOKEN);
            verify(jwtConfig).extractUserId(OLD_REFRESH_TOKEN);
            verify(tokenBlacklistService).isUserInvalidated(REFRESH_USER_ID.toString());
        }

        @Test
        @DisplayName("Should throw AuthenticationException on expired token")
        void refreshToken_withExpiredToken_shouldThrowAuthenticationException() {
            // Arrange: Simulate token expiration during user ID extraction
            when(tokenBlacklistService.isJwtBlacklisted(OLD_REFRESH_TOKEN)).thenReturn(false); // Assume not blacklisted
                                                                                               // initially
            ExpiredJwtException expiredException = new ExpiredJwtException(null, null, "expired");
            when(jwtConfig.extractUserId(OLD_REFRESH_TOKEN)).thenThrow(expiredException);
            // No need to mock extractExpiration or blacklistJwt for this specific assertion

            // Act & Assert: Verify the correct exception and cause are thrown
            assertThatThrownBy(() -> tokenService.refreshToken(OLD_REFRESH_HEADER, refreshUserDetails))
                    .isInstanceOf(AuthenticationException.class)
                    .hasMessageContaining("Token has expired") // Check the service's exception message
                    .hasCause(expiredException); // Ensure the cause is the original ExpiredJwtException

            // Verification: Verify the initial checks happened before the exception
            verify(tokenBlacklistService).isJwtBlacklisted(OLD_REFRESH_TOKEN);
            verify(jwtConfig).extractUserId(OLD_REFRESH_TOKEN);
            // No further verification needed as the exception path is the focus
        }
    }
}