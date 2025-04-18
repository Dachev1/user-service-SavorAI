package dev.idachev.userservice.service;

import dev.idachev.userservice.exception.AuthenticationException;
import dev.idachev.userservice.model.User;
import dev.idachev.userservice.repository.UserRepository;
import io.jsonwebtoken.JwtException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.util.Date;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("AuthenticationService - Logout Tests")
@MockitoSettings(strictness = Strictness.LENIENT)
class AuthenticationServiceLogoutUTest {

    @Mock
    private TokenService tokenService;
    @Mock
    private UserRepository userRepository;
    // No need for AuthenticationManager, EmailService, UserService, etc. for logout

    @InjectMocks
    private AuthenticationService authenticationService;

    private final String VALID_TOKEN = "valid.jwt.token";
    private final String AUTH_HEADER_VALID = "Bearer " + VALID_TOKEN;
    private final UUID USER_ID = UUID.randomUUID();
    private User testUser;

    @BeforeEach
    void setUp() {
        testUser = User.builder()
                .id(USER_ID)
                .username("logoutuser")
                .loggedIn(true) // Start as logged in
                .build();
    }

    @Test
    @DisplayName("Should blacklist token and mark user as logged out on successful logout")
    void logout_withValidToken_shouldBlacklistTokenAndUpdateUser() {
        // Given
        long expiryMillis = System.currentTimeMillis() + 3600000; // Token expires in 1 hour
        Date expiryDate = new Date(expiryMillis);

        when(tokenService.extractUserId(VALID_TOKEN)).thenReturn(USER_ID);
        when(tokenService.extractExpiration(VALID_TOKEN)).thenReturn(expiryDate);
        doNothing().when(tokenService).blacklistToken(eq(VALID_TOKEN), eq(expiryDate));
        when(userRepository.findById(USER_ID)).thenReturn(Optional.of(testUser));
        when(userRepository.save(any(User.class))).thenAnswer(inv -> inv.getArgument(0));

        // When
        authenticationService.logout(AUTH_HEADER_VALID);

        // Then
        // Verify token extraction was attempted (implicitly done by the method)
        verify(tokenService).extractUserId(VALID_TOKEN);
        // Verify token blacklisting with matching signature
        verify(tokenService).blacklistToken(eq(VALID_TOKEN), eq(expiryDate));
        // Verify user was fetched
        verify(userRepository).findById(USER_ID);
        // Verify user was saved with loggedIn = false
        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(userCaptor.capture());
        assertThat(userCaptor.getValue().isLoggedIn()).isFalse();
    }

    @Test
    @DisplayName("Should throw AuthenticationException when Authorization header is missing or invalid")
    void logout_withMissingOrInvalidHeader_shouldThrowAuthenticationException() {
        // Given
        String nullHeader = null;
        String invalidHeader = "Invalid Header";
        String emptyBearer = "Bearer ";

        // When & Then for null header
        assertThatThrownBy(() -> authenticationService.logout(nullHeader))
                .isInstanceOf(AuthenticationException.class)
                .hasMessageContaining("Logout requires a valid token.");

        // When & Then for invalid format
        assertThatThrownBy(() -> authenticationService.logout(invalidHeader))
                .isInstanceOf(AuthenticationException.class)
                .hasMessageContaining("Logout requires a valid token.");

        // When & Then for empty Bearer token
         assertThatThrownBy(() -> authenticationService.logout(emptyBearer))
                .isInstanceOf(AuthenticationException.class)
                .hasMessageContaining("Logout requires a valid token.");

        // Verify no service/repo interactions
        verify(tokenService, never()).extractUserId(anyString());
        verify(tokenService, never()).blacklistToken(anyString(), any(Date.class));
        verify(userRepository, never()).findById(any(UUID.class));
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    @DisplayName("Should handle token extraction failure gracefully")
    void logout_whenTokenExtractionFails_shouldAttemptBlacklistAndContinue() {
        // Given: TokenService throws exception during extraction
        when(tokenService.extractUserId(VALID_TOKEN)).thenThrow(new JwtException("Invalid signature"));
        // Assume expiration extraction might also fail or not be reached
        doNothing().when(tokenService).blacklistToken(eq(VALID_TOKEN), any(Date.class)); // Use any(Date.class) as expiry might not be extracted

        // When
        authenticationService.logout(AUTH_HEADER_VALID);

        // Then
        // Verify blacklist was still called despite extraction error
        verify(tokenService).blacklistToken(eq(VALID_TOKEN), any(Date.class));
        // Verify user update was NOT attempted as userId was not retrieved
        verify(userRepository, never()).findById(any(UUID.class));
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    @DisplayName("Should handle user not found gracefully")
    void logout_whenUserNotFound_shouldBlacklistTokenAndNotFail() {
        // Given: User repo returns empty optional
        long expiryMillis = System.currentTimeMillis() + 3600000;
        Date expiryDate = new Date(expiryMillis);
        when(tokenService.extractUserId(VALID_TOKEN)).thenReturn(USER_ID);
        when(tokenService.extractExpiration(VALID_TOKEN)).thenReturn(expiryDate);
        doNothing().when(tokenService).blacklistToken(eq(VALID_TOKEN), eq(expiryDate));
        when(userRepository.findById(USER_ID)).thenReturn(Optional.empty()); // User not found

        // When
        authenticationService.logout(AUTH_HEADER_VALID);

        // Then
        // Verify blacklist was still called
        verify(tokenService).blacklistToken(eq(VALID_TOKEN), eq(expiryDate));
        // Verify user repo was called
        verify(userRepository).findById(USER_ID);
        // Verify user was NOT saved
        verify(userRepository, never()).save(any(User.class));
    }

    // Potential test: What happens if tokenService.blacklistToken itself throws an error?
    // The current implementation logs the error but doesn't re-throw, so the method would still complete.
} 