package dev.idachev.userservice.service;

import dev.idachev.userservice.config.JwtConfig;
import dev.idachev.userservice.exception.AuthenticationException;
import dev.idachev.userservice.model.User;
import dev.idachev.userservice.security.UserPrincipal;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.test.util.ReflectionTestUtils;

import java.security.Key;
import java.util.Date;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class TokenServiceUTest {

    @Mock
    private JwtConfig jwtConfig;

    @Mock
    private TokenBlacklistService tokenBlacklistService;

    @InjectMocks
    private TokenService tokenService;

    private User testUser;
    private UserDetails userDetails;
    private String testToken;

    @BeforeEach
    void setUp() {
        testUser = new User();
        testUser.setId(UUID.randomUUID());
        testUser.setUsername("testuser");
        testUser.setEmail("test@example.com");

        userDetails = new UserPrincipal(testUser);
        testToken = "test.jwt.token";

        // Set up default mock behavior with lenient stubs to avoid "unnecessary stubbing" errors
        lenient().when(jwtConfig.generateToken(any(UserDetails.class))).thenReturn(testToken);
        lenient().when(jwtConfig.validateToken(anyString(), any(UserDetails.class))).thenReturn(true);
        lenient().when(jwtConfig.extractUsername(anyString())).thenReturn(testUser.getUsername());
        lenient().when(jwtConfig.extractUserId(anyString())).thenReturn(testUser.getId());
        lenient().when(jwtConfig.extractExpiration(anyString())).thenReturn(new Date(System.currentTimeMillis() + 3600000));
    }

    @Test
    void generateToken_WithValidUserDetails_ReturnsToken() {
        // When
        String token = tokenService.generateToken(userDetails);

        // Then
        assertNotNull(token);
        assertTrue(tokenService.validateToken(token, userDetails));
        assertEquals(testUser.getUsername(), tokenService.extractUsername(token));
        verify(jwtConfig).generateToken(userDetails);
    }

    @Test
    void generateToken_WithNullUserDetails_ThrowsException() {
        // Given
        doThrow(new IllegalArgumentException("UserDetails cannot be null")).when(jwtConfig).generateToken(null);

        // When/Then
        assertThrows(IllegalArgumentException.class, () -> 
            tokenService.generateToken(null));
    }

    @Test
    void validateToken_WithValidToken_ReturnsTrue() {
        // Given
        when(jwtConfig.validateToken(anyString(), any(UserDetails.class))).thenReturn(true);

        // When
        boolean isValid = tokenService.validateToken(testToken, userDetails);

        // Then
        assertTrue(isValid);
        verify(jwtConfig).validateToken(testToken, userDetails);
    }

    @Test
    void validateToken_WithExpiredToken_ReturnsFalse() {
        // Given
        when(jwtConfig.validateToken(anyString(), any(UserDetails.class))).thenReturn(false);

        // When
        boolean isValid = tokenService.validateToken(testToken, userDetails);

        // Then
        assertFalse(isValid);
        verify(jwtConfig).validateToken(testToken, userDetails);
    }

    @Test
    void validateToken_WithBlacklistedToken_ReturnsFalse() {
        // Given
        when(tokenBlacklistService.isBlacklisted(anyString())).thenReturn(true);
        
        // When
        boolean isValid = tokenService.validateToken(testToken, userDetails);

        // Then
        assertFalse(isValid);
        verify(tokenBlacklistService).isBlacklisted(testToken);
    }

    @Test
    void extractUsername_WithValidToken_ReturnsUsername() {
        // When
        String username = tokenService.extractUsername(testToken);

        // Then
        assertEquals(testUser.getUsername(), username);
        verify(jwtConfig).extractUsername(testToken);
    }

    @Test
    void extractUserId_WithValidToken_ReturnsUserId() {
        // When
        UUID userId = tokenService.extractUserId(testToken);

        // Then
        assertEquals(testUser.getId(), userId);
        verify(jwtConfig).extractUserId(testToken);
    }

    @Test
    void extractExpiration_WithValidToken_ReturnsDate() {
        // Given
        Date expectedDate = new Date(System.currentTimeMillis() + 3600000);
        when(jwtConfig.extractExpiration(anyString())).thenReturn(expectedDate);

        // When
        Date expirationDate = tokenService.extractExpiration(testToken);

        // Then
        assertEquals(expectedDate, expirationDate);
        verify(jwtConfig).extractExpiration(testToken);
    }

    @Test
    void blacklistToken_WithValidBearerToken_BlacklistsToken() {
        // Given
        String bearerToken = "Bearer " + testToken;
        Date expirationDate = new Date(System.currentTimeMillis() + 3600000);
        when(jwtConfig.extractExpiration(anyString())).thenReturn(expirationDate);

        // When
        boolean result = tokenService.blacklistToken(bearerToken);

        // Then
        assertTrue(result);
        verify(tokenBlacklistService).blacklistToken(eq(testToken), eq(expirationDate.getTime()));
    }

    @Test
    void blacklistToken_WithNullToken_ReturnsFalse() {
        // When
        boolean result = tokenService.blacklistToken(null);

        // Then
        assertFalse(result);
        verify(tokenBlacklistService, never()).blacklistToken(anyString(), any(Long.class));
    }

    @Test
    void blacklistToken_WithInvalidBearerToken_ReturnsFalse() {
        // Given
        String invalidToken = "Invalid Bearer token";

        // When
        boolean result = tokenService.blacklistToken(invalidToken);

        // Then
        assertFalse(result);
        verify(tokenBlacklistService, never()).blacklistToken(anyString(), any(Long.class));
    }

    @Test
    void refreshToken_WithValidToken_ReturnsNewToken() {
        // Given
        String newToken = "new.jwt.token";
        when(jwtConfig.generateToken(any(UserDetails.class))).thenReturn(newToken);

        // When
        String refreshedToken = tokenService.refreshToken(testToken, userDetails);

        // Then
        assertNotNull(refreshedToken);
        assertEquals(newToken, refreshedToken);
        verify(tokenBlacklistService).blacklistToken(eq(testToken), any(Long.class));
        verify(jwtConfig).generateToken(userDetails);
    }

    @Test
    void refreshToken_WithBlacklistedToken_ThrowsException() {
        // Given
        when(tokenBlacklistService.isBlacklisted(anyString())).thenReturn(true);

        // When/Then
        assertThrows(AuthenticationException.class, () -> 
            tokenService.refreshToken(testToken, userDetails));
    }

    @Test
    void refreshToken_WithInvalidUserId_ThrowsException() {
        // Given
        User differentUser = new User();
        differentUser.setId(UUID.randomUUID());
        differentUser.setUsername("otheruser");
        UserDetails differentUserDetails = new UserPrincipal(differentUser);

        // When/Then
        assertThrows(AuthenticationException.class, () -> 
            tokenService.refreshToken(testToken, differentUserDetails));
    }
} 