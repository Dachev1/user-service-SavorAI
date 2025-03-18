package dev.idachev.userservice.service;

import dev.idachev.userservice.config.JwtConfig;
import dev.idachev.userservice.exception.AuthenticationException;
import dev.idachev.userservice.exception.ResourceNotFoundException;
import dev.idachev.userservice.model.User;
import dev.idachev.userservice.repository.UserRepository;
import dev.idachev.userservice.web.dto.AuthResponse;
import dev.idachev.userservice.web.dto.GenericResponse;
import dev.idachev.userservice.web.dto.LoginRequest;
import dev.idachev.userservice.web.dto.UserResponse;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import io.jsonwebtoken.ExpiredJwtException;

import java.util.Date;
import java.util.Optional;

import static org.hibernate.validator.internal.util.Contracts.assertNotNull;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
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


    @Test
    void givenValidCredentials_whenLogin_thenReturnAuthResponseWithToken() {

        // Given
        LoginRequest loginRequest = LoginRequest.builder()
                .email("tes@example.com")
                .password("password123")
                .build();

        User user = User.builder()
                .email("test@example.com")
                .enabled(true)
                .loggedIn(false)
                .build();

        String token = "valid.jwt.token";

        when(userRepository.findByEmail(loginRequest.getEmail())).thenReturn(Optional.of(user));
        when(authenticationManager.authenticate(any())).thenReturn(authentication);
        when(authentication.getPrincipal()).thenReturn(user);
        when(jwtConfig.generateToken(user)).thenReturn(token);

        // When
        AuthResponse response = authenticationService.login(loginRequest);

        // Then
        assertNotNull(response);
        assertEquals(token, response.getToken());
        assertTrue(user.isLoggedIn());
        verify(userRepository).save(user);
    }

    @Test
    void givenNonexistentUser_whenLogin_thenThrowResourceNotFoundException() {

        // Given
        LoginRequest loginRequest = LoginRequest.builder()
                .email("nonexistent@example.com")
                .password("password123")
                .build();

        when(userRepository.findByEmail(loginRequest.getEmail())).thenReturn(Optional.empty());

        // When & Then
        assertThrows(ResourceNotFoundException.class, () -> authenticationService.login(loginRequest));
        verify(authenticationManager, never()).authenticate(any());
        verify(userRepository, never()).save(any());
    }

    @Test
    void givenAlreadyLoggedInUser_whenLogin_thenThrowAuthenticationException() {

        // Given
        LoginRequest loginRequest = LoginRequest.builder()
                .email("tes@example.com")
                .password("password123")
                .build();

        User user = User.builder()
                .email("test@example.com")
                .enabled(true)
                .loggedIn(true)
                .build();

        when(userRepository.findByEmail(loginRequest.getEmail())).thenReturn(Optional.of(user));

        // When & Then
        assertThrows(AuthenticationException.class, () -> authenticationService.login(loginRequest));
        verify(authenticationManager, never()).authenticate(any());
        verify(userRepository, never()).save(any());
    }

    @Test
    void givenNonVerifiedUser_whenLogin_thenThrowAuthenticationException() {

        // Given
        LoginRequest loginRequest = LoginRequest.builder()
                .email("tes@example.com")
                .password("password123")
                .build();

        User user = User.builder()
                .email("test@example.com")
                .enabled(false)
                .loggedIn(false)
                .build();

        when(userRepository.findByEmail(loginRequest.getEmail())).thenReturn(Optional.of(user));

        // When & Then
        assertThrows(AuthenticationException.class, () -> authenticationService.login(loginRequest));
        verify(authenticationManager, never()).authenticate(any());
        verify(userRepository, never()).save(any());
    }

    @Test
    void givenInvalidCredentials_whenLogin_thenThrowBadCredentialsException() {

        // Given
        LoginRequest loginRequest = LoginRequest.builder()
                .email("tes@example.com")
                .password("wrongPassword")
                .build();

        User user = User.builder()
                .email("test@example.com")
                .enabled(true)
                .loggedIn(false)
                .build();

        when(userRepository.findByEmail(loginRequest.getEmail())).thenReturn(Optional.of(user));
        when(authenticationManager.authenticate(any())).thenThrow(new BadCredentialsException("Invalid credentials"));

        // When & Then
        assertThrows(BadCredentialsException.class, () -> authenticationService.login(loginRequest));
        verify(userRepository, never()).save(any());
    }

    @Test
    void givenLoggedInUser_whenLogout_thenBlacklistTokenAndClearContext() {

        // Given
        String authHeader = "Bearer valid.jwt.token";

        User user = User.builder()
                .email("tes@example.com")
                .loggedIn(true)
                .build();

        SecurityContextHolder.setContext(securityContext);
        when(securityContext.getAuthentication()).thenReturn(authentication);
        when(authentication.isAuthenticated()).thenReturn(true);
        when(authentication.getPrincipal()).thenReturn(user);
        when(jwtConfig.extractExpiration(anyString())).thenReturn(new Date(System.currentTimeMillis() + 3600000));

        // When
        GenericResponse response = authenticationService.logout(authHeader);

        // Then
        assertNotNull(response);
        assertEquals(200, response.getStatus());
        assertEquals("Logged out successfully", response.getMessage());
        assertFalse(user.isLoggedIn());
        verify(userRepository).save(user);
        verify(tokenBlacklistService).blacklistToken(anyString(), anyLong());
    }

    @Test
    void givenNoAuthentication_whenLogout_thenJustClearContext() {

        // Given
        String authHeader = "Bearer valid.jwt.token";

        SecurityContextHolder.setContext(securityContext);
        when(securityContext.getAuthentication()).thenReturn(null);
        when(jwtConfig.extractExpiration(anyString())).thenReturn(new Date(System.currentTimeMillis() + 3600000));

        // When
        GenericResponse response = authenticationService.logout(authHeader);

        // Then
        assertNotNull(response);
        assertEquals(200, response.getStatus());
        assertEquals("Logged out successfully", response.getMessage());
        verify(userRepository, never()).save(any());
        verify(tokenBlacklistService).blacklistToken(anyString(), anyLong());
    }

    @Test
    void givenNonUserPrincipal_whenLogout_thenJustClearContext() {

        // Given
        String authHeader = "Bearer valid.jwt.token";
        String nonUserPrincipal = "string-principal";

        SecurityContextHolder.setContext(securityContext);
        when(securityContext.getAuthentication()).thenReturn(authentication);
        when(authentication.isAuthenticated()).thenReturn(true);
        when(authentication.getPrincipal()).thenReturn(nonUserPrincipal);
        when(jwtConfig.extractExpiration(anyString())).thenReturn(new Date(System.currentTimeMillis() + 3600000));

        //When
        GenericResponse response = authenticationService.logout(authHeader);

        // Then
        assertNotNull(response);
        assertEquals(200, response.getStatus());
        assertEquals("Logged out successfully", response.getMessage());
        verify(userRepository, never()).save(any());
        verify(tokenBlacklistService).blacklistToken(anyString(), anyLong());
    }

    @Test
    void givenNonBearerAuthHeader_whenLogout_thenOnlyClearContext() {

        // Given
        String authHeader = "Basic dXNlcjpwYXNzd29yZA";

        SecurityContextHolder.setContext(securityContext);
        when(securityContext.getAuthentication()).thenReturn(null);

        // When
        GenericResponse response = authenticationService.logout(authHeader);

        // Then
        Assertions.assertNotNull(response);
        assertEquals(200, response.getStatus());
        assertEquals("Logged out successfully", response.getMessage());
        verify(tokenBlacklistService, never()).blacklistToken(anyString(), anyLong());
    }

    @Test
    void givenExpiredToken_whenLogout_thenHandleGracefully() {

        // Given
        String authHeader = "Bearer expired.jwt.token";

        SecurityContextHolder.setContext(securityContext);
        when(securityContext.getAuthentication()).thenReturn(null);
        when(jwtConfig.extractExpiration(anyString())).thenThrow(new ExpiredJwtException(null, null, "Token expired"));

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

        // Given
        SecurityContextHolder.setContext(securityContext);
        when(securityContext.getAuthentication()).thenReturn(null);

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
        when(jwtConfig.generateToken(user)).thenReturn(token);

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

        SecurityContextHolder.setContext(securityContext);
        when(securityContext.getAuthentication()).thenReturn(authentication);
        when(authentication.isAuthenticated()).thenReturn(true);
        when(authentication.getPrincipal()).thenReturn(user);

        // When
        User currentUser = authenticationService.getCurrentUser();

        // Then
        assertNotNull(currentUser);
        assertEquals(user, currentUser);
    }

    @Test
    void givenNoAuthentication_whenGetCurrentUser_thenThrowAuthenticationException() {

        // Given
        SecurityContextHolder.setContext(securityContext);
        when(securityContext.getAuthentication()).thenReturn(null);

        // When & Then
        assertThrows(AuthenticationException.class, () -> authenticationService.getCurrentUser());
    }

    @Test
    void givenNonUserPrincipal_whenGetCurrentUser_thenThrowAuthenticationException() {

        // Given
        String nonUserPrincipal = "non-user-principal";

        SecurityContextHolder.setContext(securityContext);
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

        SecurityContextHolder.setContext(securityContext);
        when(securityContext.getAuthentication()).thenReturn(authentication);
        when(authentication.isAuthenticated()).thenReturn(true);
        when(authentication.getPrincipal()).thenReturn(user);

        // When
        UserResponse result = authenticationService.getCurrentUserInfo();

        // Then
        assertNotNull(result);
        assertEquals(user.getUsername(), result.getUsername());
        assertEquals(user.getEmail(), result.getEmail());
        assertEquals(user.isEnabled(), result.isVerified());
    }
}
