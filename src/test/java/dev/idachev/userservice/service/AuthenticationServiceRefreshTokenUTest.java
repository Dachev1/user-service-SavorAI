package dev.idachev.userservice.service;

import dev.idachev.userservice.exception.AuthenticationException;
import dev.idachev.userservice.exception.UserNotFoundException;
import dev.idachev.userservice.mapper.DtoMapper;
import dev.idachev.userservice.model.User;
import dev.idachev.userservice.repository.UserRepository;
import dev.idachev.userservice.security.UserPrincipal;
import dev.idachev.userservice.web.dto.AuthResponse;
import dev.idachev.userservice.web.dto.UserResponse;
import io.jsonwebtoken.JwtException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.util.Date;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("AuthenticationService - Refresh Token Tests")
@MockitoSettings(strictness = Strictness.LENIENT)
class AuthenticationServiceRefreshTokenUTest {

    @Mock
    private TokenService tokenService;
    @Mock
    private UserRepository userRepository;

    @InjectMocks
    private AuthenticationService authenticationService;

    private MockedStatic<DtoMapper> dtoMapperMockedStatic;

    private final String OLD_VALID_TOKEN = "old.valid.jwt.token";
    private final String AUTH_HEADER_VALID = "Bearer " + OLD_VALID_TOKEN;
    private final UUID USER_ID = UUID.randomUUID();
    private User testUser;
    private UserPrincipal testUserPrincipal;

    @BeforeEach
    void setUp() {
        dtoMapperMockedStatic = Mockito.mockStatic(DtoMapper.class);
        testUser = User.builder()
                .id(USER_ID)
                .username("refreshtest")
                .enabled(true)
                .banned(false)
                .build();
        testUserPrincipal = new UserPrincipal(testUser);
    }

    @AfterEach
    void tearDown() {
        dtoMapperMockedStatic.close();
    }

    @Test
    @DisplayName("Should refresh token successfully and return new AuthResponse")
    void refreshToken_withValidNonBlacklistedToken_shouldReturnNewToken() {
        // Given
        String newGeneratedToken = "new.jwt.token.string";
        Date expiryDate = new Date(System.currentTimeMillis() + 10000); // Expires soon
        UserResponse embeddedUserResponse = UserResponse.builder().id(USER_ID).username(testUser.getUsername()).build();
        AuthResponse expectedResponse = AuthResponse.builder()
                                            .token(newGeneratedToken)
                                            .user(embeddedUserResponse)
                                            .username(testUser.getUsername())
                                            .build();

        // Mock token checks and extraction
        when(tokenService.isJwtBlacklisted(OLD_VALID_TOKEN)).thenReturn(false); // Not blacklisted initially
        when(tokenService.extractUserId(OLD_VALID_TOKEN)).thenReturn(USER_ID);
        when(tokenService.extractExpiration(OLD_VALID_TOKEN)).thenReturn(expiryDate);
        when(tokenService.isUserInvalidated(USER_ID)).thenReturn(false); // User not invalidated

        // Mock user repository
        when(userRepository.findById(USER_ID)).thenReturn(Optional.of(testUser));

        // Mock blacklisting the old token - needs Date argument now
        doNothing().when(tokenService).blacklistToken(eq(OLD_VALID_TOKEN), any(Date.class));

        // Mock new token generation
        when(tokenService.generateToken(any(UserPrincipal.class))).thenReturn(newGeneratedToken);

        // Mock DTO mapping
        dtoMapperMockedStatic.when(() -> DtoMapper.mapToAuthResponse(eq(testUser), eq(newGeneratedToken)))
                               .thenReturn(expectedResponse);

        // When
        AuthResponse actualResponse = authenticationService.refreshToken(AUTH_HEADER_VALID);

        // Then
        assertThat(actualResponse).isNotNull();
        assertThat(actualResponse.getToken()).isEqualTo(newGeneratedToken);
        assertThat(actualResponse.getUser().getId()).isEqualTo(USER_ID);

        // Verify sequence
        verify(tokenService).isJwtBlacklisted(OLD_VALID_TOKEN); // Initial blacklist check
        verify(tokenService).extractUserId(OLD_VALID_TOKEN);
        verify(userRepository).findById(USER_ID);
        verify(tokenService).isUserInvalidated(USER_ID); // Second invalidation check
        verify(tokenService).blacklistToken(eq(OLD_VALID_TOKEN), any(Date.class)); // Blacklist the old one
        verify(tokenService).generateToken(argThat(principal -> {
            UserPrincipal userPrincipal = (UserPrincipal) principal; // Cast is necessary
            return userPrincipal.user().getId().equals(USER_ID); // Use user() accessor
        })); // Generate new one
        dtoMapperMockedStatic.verify(() -> DtoMapper.mapToAuthResponse(testUser, newGeneratedToken));
    }

    @Test
    @DisplayName("Should throw AuthenticationException for missing or invalid header")
    void refreshToken_withMissingOrInvalidHeader_shouldThrowAuthenticationException() {
        // Given
        String nullHeader = null;
        String invalidHeader = "InvalidTokenFormat";

        // When & Then
        assertThatThrownBy(() -> authenticationService.refreshToken(nullHeader))
                .isInstanceOf(AuthenticationException.class)
                .hasMessageContaining("Invalid or missing Authorization header");

        assertThatThrownBy(() -> authenticationService.refreshToken(invalidHeader))
                 .isInstanceOf(AuthenticationException.class)
                .hasMessageContaining("Invalid or missing Authorization header");

        verifyNoInteractions(tokenService, userRepository); // Check no further calls
    }

    @Test
    @DisplayName("Should throw AuthenticationException if token is already blacklisted")
    void refreshToken_whenTokenIsBlacklisted_shouldThrowAuthenticationException() {
        // Given
        when(tokenService.isJwtBlacklisted(OLD_VALID_TOKEN)).thenReturn(true); // Token is blacklisted

        // When & Then
        assertThatThrownBy(() -> authenticationService.refreshToken(AUTH_HEADER_VALID))
                .isInstanceOf(AuthenticationException.class)
                .hasMessageContaining("Token is blacklisted or has been logged out");

        // Verify only the first blacklist check happened
        verify(tokenService).isJwtBlacklisted(OLD_VALID_TOKEN);
        verify(tokenService, never()).extractUserId(anyString());
        verifyNoInteractions(userRepository);
    }

     @Test
    @DisplayName("Should throw AuthenticationException if user is invalidated")
    void refreshToken_whenUserIsInvalidated_shouldThrowAuthenticationException() {
        // Given
        Date expiryDate = new Date(System.currentTimeMillis() + 10000);
        when(tokenService.isJwtBlacklisted(OLD_VALID_TOKEN)).thenReturn(false);
        when(tokenService.extractUserId(OLD_VALID_TOKEN)).thenReturn(USER_ID);
        when(tokenService.extractExpiration(OLD_VALID_TOKEN)).thenReturn(expiryDate);
        when(userRepository.findById(USER_ID)).thenReturn(Optional.of(testUser));
        when(tokenService.isUserInvalidated(USER_ID)).thenReturn(true); // User is invalidated

        // When & Then
        assertThatThrownBy(() -> authenticationService.refreshToken(AUTH_HEADER_VALID))
                .isInstanceOf(AuthenticationException.class)
                .hasMessageContaining("Token has been invalidated");

        // Verify checks up to isUserInvalidated
        verify(tokenService).isJwtBlacklisted(OLD_VALID_TOKEN);
        verify(tokenService).extractUserId(OLD_VALID_TOKEN);
        verify(userRepository).findById(USER_ID);
        verify(tokenService).isUserInvalidated(USER_ID);
        verify(tokenService, never()).blacklistToken(anyString(), any(Date.class)); // Old token not blacklisted yet
        verify(tokenService, never()).generateToken(any());
    }

    @Test
    @DisplayName("Should throw UserNotFoundException if user for token not found")
    void refreshToken_whenUserNotFound_shouldThrowUserNotFoundException() {
        // Given
        Date expiryDate = new Date(System.currentTimeMillis() + 10000);
        when(tokenService.isJwtBlacklisted(OLD_VALID_TOKEN)).thenReturn(false);
        when(tokenService.extractUserId(OLD_VALID_TOKEN)).thenReturn(USER_ID);
        when(tokenService.extractExpiration(OLD_VALID_TOKEN)).thenReturn(expiryDate);
        when(userRepository.findById(USER_ID)).thenReturn(Optional.empty()); // User not found

        // When & Then
        assertThatThrownBy(() -> authenticationService.refreshToken(AUTH_HEADER_VALID))
                .isInstanceOf(UserNotFoundException.class)
                .hasMessageContaining("User not found for token");

        verify(userRepository).findById(USER_ID);
        verify(tokenService, never()).isUserInvalidated(any(UUID.class));
        verify(tokenService, never()).blacklistToken(anyString(), any(Date.class));
        verify(tokenService, never()).generateToken(any());
    }

     @Test
    @DisplayName("Should re-throw JwtException on token extraction failure")
    void refreshToken_whenTokenExtractionFails_shouldThrowJwtException() {
        // Given
        when(tokenService.isJwtBlacklisted(OLD_VALID_TOKEN)).thenReturn(false);
        when(tokenService.extractUserId(OLD_VALID_TOKEN)).thenThrow(new JwtException("Bad token"));

        // When & Then
        assertThatThrownBy(() -> authenticationService.refreshToken(AUTH_HEADER_VALID))
                .isInstanceOf(JwtException.class)
                .hasMessageContaining("Bad token");

         verify(tokenService).isJwtBlacklisted(OLD_VALID_TOKEN);
         verify(tokenService).extractUserId(OLD_VALID_TOKEN);
         verifyNoInteractions(userRepository);
         verify(tokenService, never()).blacklistToken(anyString(), any(Date.class));
         verify(tokenService, never()).generateToken(any());
    }
} 