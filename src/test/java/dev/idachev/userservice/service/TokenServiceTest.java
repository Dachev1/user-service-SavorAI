package dev.idachev.userservice.service;

import dev.idachev.userservice.config.JwtConfig;
import dev.idachev.userservice.exception.InvalidTokenException;
import dev.idachev.userservice.model.Role;
import dev.idachev.userservice.model.User;
import dev.idachev.userservice.security.UserPrincipal;
import io.jsonwebtoken.JwtException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.LocalDateTime;
import java.util.Date;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class TokenServiceUTest {

    @Mock
    private JwtConfig jwtConfig;
    
    @Mock
    private TokenBlacklistService tokenBlacklistService;
    
    private TokenService tokenService;
    
    private User testUser;
    private UserPrincipal userPrincipal;
    private UUID userId;
    private String validToken;
    
    @BeforeEach
    void setUp() {
        tokenService = new TokenService(jwtConfig, tokenBlacklistService);
        
        userId = UUID.randomUUID();
        testUser = User.builder()
                .id(userId)
                .username("testuser")
                .email("test@example.com")
                .password("encodedPassword")
                .role(Role.USER)
                .enabled(true)
                .createdOn(LocalDateTime.now())
                .updatedOn(LocalDateTime.now())
                .build();
                
        userPrincipal = new UserPrincipal(testUser);
        validToken = "valid.jwt.token";
    }
    
    @Test
    @DisplayName("Should generate token successfully")
    void should_GenerateToken_Successfully() {
        // Given
        when(jwtConfig.generateToken(userPrincipal)).thenReturn(validToken);
        
        // When
        String result = tokenService.generateToken(userPrincipal);
        
        // Then
        assertThat(result).isEqualTo(validToken);
    }
    
    @Test
    @DisplayName("Should blacklist token successfully")
    void should_BlacklistToken_Successfully() {
        // Given
        String bearerToken = "Bearer " + validToken;
        Date expirationDate = new Date(System.currentTimeMillis() + 3600000); // 1 hour in future
        
        when(jwtConfig.extractExpiration(validToken)).thenReturn(expirationDate);
        
        // When
        boolean result = tokenService.blacklistToken(bearerToken);
        
        // Then
        verify(tokenBlacklistService).blacklistToken(eq(validToken), anyLong());
        assertThat(result).isTrue();
    }
    
    @Test
    @DisplayName("Should not blacklist invalid token")
    void should_NotBlacklistInvalidToken_WhenTokenIsInvalid() {
        // Given
        String invalidToken = null;
        
        // When
        boolean result = tokenService.blacklistToken(invalidToken);
        
        // Then
        assertThat(result).isFalse();
        verify(tokenBlacklistService, never()).blacklistToken(anyString(), anyLong());
    }
    
    @Test
    @DisplayName("Should check if token is blacklisted correctly")
    void should_CheckIfTokenIsBlacklisted_Correctly() {
        // Given
        when(tokenBlacklistService.isBlacklisted(validToken)).thenReturn(true);
        
        // When
        boolean result = tokenService.isTokenBlacklisted(validToken);
        
        // Then
        assertThat(result).isTrue();
    }
    
    @Test
    @DisplayName("Should extract user ID from token successfully")
    void should_ExtractUserIdFromToken_Successfully() {
        // Given
        when(jwtConfig.extractUserId(validToken)).thenReturn(userId);
        
        // When
        UUID result = tokenService.extractUserId(validToken);
        
        // Then
        assertThat(result).isEqualTo(userId);
    }
    
    @Test
    @DisplayName("Should throw InvalidTokenException when extracting user ID from invalid token")
    void should_ThrowInvalidTokenException_When_ExtractingUserIdFromInvalidToken() {
        // Given
        String invalidToken = "invalid.token";
        when(jwtConfig.extractUserId(invalidToken)).thenThrow(new JwtException("Invalid token"));
        
        // When/Then
        assertThatThrownBy(() -> tokenService.extractUserId(invalidToken))
                .isInstanceOf(InvalidTokenException.class)
                .hasMessageContaining("Invalid token format");
    }
    
    @Test
    @DisplayName("Should validate token successfully")
    void should_ValidateToken_Successfully() {
        // Given
        String bearerToken = "Bearer " + validToken;
        
        when(tokenBlacklistService.isBlacklisted(validToken)).thenReturn(false);
        when(tokenBlacklistService.isBlacklisted("user_tokens_invalidated:" + userId)).thenReturn(false);
        when(jwtConfig.validateToken(validToken, userPrincipal)).thenReturn(true);
        
        // When
        boolean result = tokenService.validateToken(bearerToken, userPrincipal);
        
        // Then
        assertThat(result).isTrue();
    }
    
    @Test
    @DisplayName("Should invalidate user tokens successfully")
    void should_InvalidateUserTokens_Successfully() {
        // Given
        String userTokensKey = "user_tokens_invalidated:" + userId;
        
        // When
        tokenService.invalidateUserTokens(userId);
        
        // Then
        verify(tokenBlacklistService).blacklistToken(eq(userTokensKey), anyLong());
    }
    
    @Test
    @DisplayName("Should not invalidate tokens for null user ID")
    void should_NotInvalidateTokens_ForNullUserId() {
        // Given
        UUID nullUserId = null;
        
        // When
        tokenService.invalidateUserTokens(nullUserId);
        
        // Then
        verify(tokenBlacklistService, never()).blacklistToken(anyString(), anyLong());
    }
} 