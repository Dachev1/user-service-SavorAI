package dev.idachev.userservice.service;

import dev.idachev.userservice.config.JwtConfig;
import dev.idachev.userservice.exception.AuthenticationException;
import dev.idachev.userservice.exception.ResourceNotFoundException;
import dev.idachev.userservice.model.User;
import dev.idachev.userservice.repository.UserRepository;
import dev.idachev.userservice.security.UserPrincipal;
import dev.idachev.userservice.web.dto.AuthResponse;
import dev.idachev.userservice.web.dto.GenericResponse;
import dev.idachev.userservice.web.dto.LoginRequest;
import dev.idachev.userservice.web.dto.UserResponse;
import io.jsonwebtoken.ExpiredJwtException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

import java.time.LocalDateTime;
import java.util.Date;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class AuthenticationServiceUTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private JwtConfig jwtConfig;

    @Mock
    private AuthenticationManager authenticationManager;

    @Mock
    private TokenBlacklistService tokenBlacklistService;

    @Mock
    private Authentication authentication;

    @Mock
    private SecurityContext securityContext;

    @InjectMocks
    private AuthenticationService authenticationService;

    @BeforeEach
    void setUp() {
        SecurityContextHolder.setContext(securityContext);
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void givenValidCredentials_whenLogin_thenReturnAuthResponseWithToken() {

        // Given
        String email = "test@example.com";
        String password = "password";
        LoginRequest request = LoginRequest.builder()
                .identifier(email)
                .password(password)
                .build();

        User user = User.builder()
                .email(email)
                .enabled(true)
                .build();

        UserPrincipal userPrincipal = new UserPrincipal(user);
        String token = "valid.jwt.token";

        when(userRepository.findByEmail(email)).thenReturn(Optional.of(user));
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(authentication);
        when(authentication.getPrincipal()).thenReturn(userPrincipal);
        when(jwtConfig.generateToken(userPrincipal)).thenReturn(token);

        // When
        AuthResponse response = authenticationService.login(request);

        // Then
        assertNotNull(response);
        assertEquals(token, response.getToken());
        assertEquals(email, response.getEmail());
        assertTrue(response.isSuccess());

        verify(userRepository).save(user);
    }

    @Test
    void givenNonexistentUser_whenLogin_thenThrowResourceNotFoundException() {

        // Given
        String nonExistentEmail = "nonexistent@example.com";
        LoginRequest request = LoginRequest.builder()
                .identifier(nonExistentEmail)
                .password("password")
                .build();

        when(userRepository.findByEmail(nonExistentEmail)).thenReturn(Optional.empty());

        // When & Then
        assertThrows(ResourceNotFoundException.class, () -> authenticationService.login(request));
    }

    @Test
    void givenAlreadyLoggedInUser_whenLogin_thenThrowAuthenticationException() {

        // Given
        String email = "test@example.com";
        LoginRequest request = LoginRequest.builder()
                .identifier(email)
                .password("password")
                .build();

        User user = User.builder()
                .email(email)
                .enabled(true)
                .loggedIn(true) // Already logged in
                .build();

        when(userRepository.findByEmail(email)).thenReturn(Optional.of(user));

        // When & Then
        assertThrows(AuthenticationException.class, () -> authenticationService.login(request));
    }

    @Test
    void givenNonVerifiedUser_whenLogin_thenThrowAuthenticationException() {

        // Given
        String email = "test@example.com";
        LoginRequest request = LoginRequest.builder()
                .identifier(email)
                .password("password")
                .build();

        User user = User.builder()
                .email(email)
                .enabled(false) // Not verified
                .build();

        when(userRepository.findByEmail(email)).thenReturn(Optional.of(user));

        // When & Then
        assertThrows(AuthenticationException.class, () -> authenticationService.login(request));
    }

    @Test
    void givenInvalidCredentials_whenLogin_thenThrowBadCredentialsException() {

        // Given
        String email = "test@example.com";
        String password = "wrong_password";
        LoginRequest request = LoginRequest.builder()
                .identifier(email)
                .password(password)
                .build();

        User user = User.builder()
                .email(email)
                .enabled(true)
                .build();

        when(userRepository.findByEmail(email)).thenReturn(Optional.of(user));
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenThrow(new BadCredentialsException("Invalid credentials"));

        // When & Then
        assertThrows(BadCredentialsException.class, () -> authenticationService.login(request));
    }

    @Test
    void givenLoggedInUser_whenLogout_thenBlacklistTokenAndClearContext() {

        // Given
        String authHeader = "Bearer valid.jwt.token";
        String token = "valid.jwt.token";
        Date expiryDate = new Date(System.currentTimeMillis() + 3600000); // 1 hour in future

        User user = User.builder()
                .email("test@example.com")
                .loggedIn(true)
                .build();

        UserPrincipal userPrincipal = new UserPrincipal(user);

        when(securityContext.getAuthentication()).thenReturn(authentication);
        when(authentication.isAuthenticated()).thenReturn(true);
        when(authentication.getPrincipal()).thenReturn(userPrincipal);
        when(jwtConfig.extractExpiration(token)).thenReturn(expiryDate);

        // When
        GenericResponse response = authenticationService.logout(authHeader);

        // Then
        assertNotNull(response);
        assertEquals(200, response.getStatus());
        assertEquals("Logged out successfully", response.getMessage());
        assertFalse(user.isLoggedIn());

        // Verify token blacklisting and context clearing
        verify(userRepository).save(user);
        verify(tokenBlacklistService).blacklistToken(eq(token), anyLong());
    }

    @Test
    void givenNoAuthentication_whenLogout_thenJustClearContext() {

        // Given
        String authHeader = "Bearer valid.jwt.token";
        String token = "valid.jwt.token";
        Date expiryDate = new Date(System.currentTimeMillis() + 3600000); // 1 hour in future

        when(securityContext.getAuthentication()).thenReturn(null);
        when(jwtConfig.extractExpiration(token)).thenReturn(expiryDate);

        // When
        GenericResponse response = authenticationService.logout(authHeader);

        // Then
        assertNotNull(response);
        assertEquals(200, response.getStatus());
        assertEquals("Logged out successfully", response.getMessage());

        // Verify token blacklisting only
        verify(userRepository, never()).save(any(User.class));
        verify(tokenBlacklistService).blacklistToken(eq(token), anyLong());
    }

    @Test
    void givenNonUserPrincipal_whenLogout_thenJustClearContext() {

        // Given
        String authHeader = "Bearer valid.jwt.token";
        String token = "valid.jwt.token";
        Date expiryDate = new Date(System.currentTimeMillis() + 3600000); // 1 hour in future
        String nonUserPrincipal = "non-user-principal";

        when(securityContext.getAuthentication()).thenReturn(authentication);
        when(authentication.isAuthenticated()).thenReturn(true);
        when(authentication.getPrincipal()).thenReturn(nonUserPrincipal);
        when(jwtConfig.extractExpiration(token)).thenReturn(expiryDate);

        // When
        GenericResponse response = authenticationService.logout(authHeader);

        // Then
        assertNotNull(response);
        assertEquals(200, response.getStatus());
        assertEquals("Logged out successfully", response.getMessage());

        // Verify token blacklisting only
        verify(userRepository, never()).save(any(User.class));
        verify(tokenBlacklistService).blacklistToken(eq(token), anyLong());
    }

    @Test
    void givenNonBearerAuthHeader_whenLogout_thenOnlyClearContext() {

        // Given
        String authHeader = "Basic dXNlcjpwYXNzd29yZA=="; // Basic auth header

        // When
        GenericResponse response = authenticationService.logout(authHeader);

        // Then
        assertNotNull(response);
        assertEquals(200, response.getStatus());
        assertEquals("Logged out successfully", response.getMessage());
        verify(tokenBlacklistService, never()).blacklistToken(anyString(), anyLong());
    }

    @Test
    void givenExpiredToken_whenLogout_thenHandleGracefully() {

        // Given
        String authHeader = "Bearer expired.token";
        String token = "expired.token";

        when(jwtConfig.extractExpiration(token)).thenThrow(new ExpiredJwtException(null, null, "Token expired"));

        // When
        GenericResponse response = authenticationService.logout(authHeader);

        // Then
        assertNotNull(response);
        assertEquals(200, response.getStatus());
        assertEquals("Logged out successfully", response.getMessage());
        verify(tokenBlacklistService, never()).blacklistToken(anyString(), anyLong());
    }

    @Test
    void givenNullAuthHeader_whenLogout_thenHandleGracefully() {

        // When
        GenericResponse response = authenticationService.logout(null);

        // Then
        assertNotNull(response);
        assertEquals(200, response.getStatus());
        assertEquals("Logged out successfully", response.getMessage());
        verify(tokenBlacklistService, never()).blacklistToken(anyString(), anyLong());
    }

    @Test
    void givenValidEmail_whenGetVerificationStatus_thenReturnAuthResponseWithToken() {

        // Given
        String email = "test@example.com";

        User user = User.builder()
                .email(email)
                .enabled(true)
                .build();

        String token = "valid.jwt.token";

        when(userRepository.findByEmail(email)).thenReturn(Optional.of(user));
        when(jwtConfig.generateToken(any(UserPrincipal.class))).thenReturn(token);

        // When
        AuthResponse response = authenticationService.getVerificationStatus(email);

        // Then
        assertNotNull(response);
        assertEquals(token, response.getToken());
    }

    @Test
    void givenNonVerifiedUser_whenGetVerificationStatus_thenReturnAuthResponseWithoutToken() {

        // Given
        String email = "test@example.com";

        User user = User.builder()
                .email(email)
                .enabled(false)
                .build();

        when(userRepository.findByEmail(email)).thenReturn(Optional.of(user));

        // When
        AuthResponse response = authenticationService.getVerificationStatus(email);

        // Then
        assertNotNull(response);
        assertEquals("", response.getToken());
        verify(jwtConfig, never()).generateToken(any());
    }

    @Test
    void givenNonexistentUser_whenGetVerificationStatus_thenThrowResourceNotFoundException() {

        // Given
        String email = "nonexistent@example.com";

        when(userRepository.findByEmail(email)).thenReturn(Optional.empty());

        // When & Then
        assertThrows(ResourceNotFoundException.class, () -> authenticationService.getVerificationStatus(email));
    }

    @Test
    void givenAuthenticatedUser_whenGetCurrentUser_thenReturnUser() {

        // Given
        User user = User.builder()
                .email("test@example.com")
                .build();
        
        UserPrincipal userPrincipal = new UserPrincipal(user);

        when(securityContext.getAuthentication()).thenReturn(authentication);
        when(authentication.isAuthenticated()).thenReturn(true);
        when(authentication.getPrincipal()).thenReturn(userPrincipal);

        // When
        User currentUser = authenticationService.getCurrentUser();

        // Then
        assertNotNull(currentUser);
        assertEquals(user, currentUser);
    }

    @Test
    void givenNoAuthentication_whenGetCurrentUser_thenThrowAuthenticationException() {

        // Given
        when(securityContext.getAuthentication()).thenReturn(null);

        // When & Then
        assertThrows(AuthenticationException.class, () -> authenticationService.getCurrentUser());
    }

    @Test
    void givenNonUserPrincipal_whenGetCurrentUser_thenThrowAuthenticationException() {

        // Given
        String nonUserPrincipal = "non-user-principal";

        when(securityContext.getAuthentication()).thenReturn(authentication);
        when(authentication.isAuthenticated()).thenReturn(true);
        when(authentication.getPrincipal()).thenReturn(nonUserPrincipal);

        // When & Then
        assertThrows(AuthenticationException.class, () -> authenticationService.getCurrentUser());
    }

    @Test
    void givenAuthenticatedUser_whenGetCurrentUserInfo_thenReturnUserResponse() {

        // Given
        User user = User.builder()
                .username("testuser")
                .email("test@example.com")
                .enabled(true) // This should map to verified in UserResponse
                .build();
                
        UserPrincipal userPrincipal = new UserPrincipal(user);

        when(securityContext.getAuthentication()).thenReturn(authentication);
        when(authentication.isAuthenticated()).thenReturn(true);
        when(authentication.getPrincipal()).thenReturn(userPrincipal);

        // When
        UserResponse result = authenticationService.getCurrentUserInfo();

        // Then
        assertNotNull(result);
        assertEquals(user.getUsername(), result.getUsername());
        assertEquals(user.getEmail(), result.getEmail());
        assertEquals(user.isEnabled(), result.isVerified());
    }
}
