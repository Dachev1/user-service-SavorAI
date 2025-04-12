package dev.idachev.userservice.integration;

import dev.idachev.userservice.config.JwtConfig;
import dev.idachev.userservice.exception.AuthenticationException;
import dev.idachev.userservice.model.Role;
import dev.idachev.userservice.model.User;
import dev.idachev.userservice.repository.UserRepository;
import dev.idachev.userservice.security.UserPrincipal;
import dev.idachev.userservice.service.TokenBlacklistService;
import dev.idachev.userservice.service.TokenService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Date;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

@SpringBootTest
@ActiveProfiles("test")
@Transactional
public class TokenServiceITest {

    @Autowired
    private TokenService tokenService;
    
    @Autowired
    private JwtConfig jwtConfig;
    
    @Autowired
    private UserRepository userRepository;
    
    @Autowired
    private TokenBlacklistService tokenBlacklistService;
    
    private User testUser;
    private UUID testUserId;
    private String testToken;
    private UserPrincipal userPrincipal;

    @BeforeEach
    void setUp() {
        // Clear database
        userRepository.deleteAll();
        
        // Create test user
        testUser = User.builder()
                .username("testuser")
                .email("test@example.com")
                .password("encodedPassword")
                .role(Role.USER)
                .enabled(true)
                .createdOn(LocalDateTime.now())
                .updatedOn(LocalDateTime.now())
                .build();
        
        testUser = userRepository.save(testUser);
        testUserId = testUser.getId();
        
        // Create UserPrincipal
        userPrincipal = new UserPrincipal(testUser);
        
        // Generate a test token
        testToken = tokenService.generateToken(userPrincipal);
    }
    
    @Test
    @DisplayName("Should generate a valid token")
    void testGenerateToken() {
        // When
        String token = tokenService.generateToken(userPrincipal);
        
        // Then
        assertThat(token).isNotNull();
        assertThat(token).isNotEmpty();
        
        // Verify token contents
        String username = tokenService.extractUsername(token);
        UUID userId = tokenService.extractUserId(token);
        Date expiration = tokenService.extractExpiration(token);
        
        assertThat(username).isEqualTo("testuser");
        assertThat(userId).isEqualTo(testUserId);
        assertThat(expiration).isAfter(new Date());
    }
    
    @Test
    @DisplayName("Should validate a valid token")
    void testValidateToken() {
        // When
        boolean isValid = tokenService.validateToken(testToken, userPrincipal);
        
        // Then
        assertThat(isValid).isTrue();
    }
    
    @Test
    @DisplayName("Should validate a token with Bearer prefix")
    void testValidateTokenWithBearerPrefix() {
        // Given
        String tokenWithPrefix = "Bearer " + testToken;
        
        // When
        boolean isValid = tokenService.validateToken(tokenWithPrefix, userPrincipal);
        
        // Then
        assertThat(isValid).isTrue();
    }
    
    @Test
    @DisplayName("Should reject an invalid token")
    void testValidateInvalidToken() {
        // Given
        String invalidToken = testToken + "invalid";
        
        // When
        boolean isValid = tokenService.validateToken(invalidToken, userPrincipal);
        
        // Then
        assertThat(isValid).isFalse();
    }
    
    @Test
    @DisplayName("Should extract user ID from token")
    void testExtractUserId() {
        // When
        UUID userId = tokenService.extractUserId(testToken);
        
        // Then
        assertThat(userId).isEqualTo(testUserId);
    }
    
    @Test
    @DisplayName("Should extract username from token")
    void testExtractUsername() {
        // When
        String username = tokenService.extractUsername(testToken);
        
        // Then
        assertThat(username).isEqualTo("testuser");
    }
    
    @Test
    @DisplayName("Should extract expiration from token")
    void testExtractExpiration() {
        // When
        Date expiration = tokenService.extractExpiration(testToken);
        
        // Then
        assertThat(expiration).isAfter(new Date());
    }
    
    @Test
    @DisplayName("Should blacklist a token")
    void testBlacklistToken() {
        // When
        boolean blacklisted = tokenService.blacklistToken(testToken);
        
        // Then
        assertThat(blacklisted).isTrue();
        assertThat(tokenService.isTokenBlacklisted(testToken)).isTrue();
    }
    
    @Test
    @DisplayName("Should detect blacklisted token")
    void testIsTokenBlacklisted() {
        // Given
        tokenService.blacklistToken(testToken);
        
        // When
        boolean isBlacklisted = tokenService.isTokenBlacklisted(testToken);
        
        // Then
        assertThat(isBlacklisted).isTrue();
    }
    
    @Test
    @DisplayName("Should refresh token")
    void testRefreshToken() throws AuthenticationException {
        // When
        String refreshedToken = tokenService.refreshToken(testToken, userPrincipal);
        
        // Then
        assertThat(refreshedToken).isNotNull();
        assertThat(refreshedToken).isNotEqualTo(testToken);
        
        // Verify original token is now blacklisted
        assertThat(tokenService.isTokenBlacklisted(testToken)).isTrue();
        
        // Verify new token is valid
        assertThat(tokenService.validateToken(refreshedToken, userPrincipal)).isTrue();
    }
    
    @Test
    @DisplayName("Should not refresh blacklisted token")
    void testRefreshBlacklistedToken() {
        // Given
        tokenService.blacklistToken(testToken);
        
        // When/Then
        assertThatThrownBy(() -> tokenService.refreshToken(testToken, userPrincipal))
                .isInstanceOf(AuthenticationException.class)
                .hasMessageContaining("Token is blacklisted");
    }
    
    @Test
    @DisplayName("Should not refresh token for banned user")
    void testRefreshTokenForBannedUser() {
        // Given
        testUser.setBanned(true);
        userRepository.save(testUser);
        
        // When/Then
        assertThatThrownBy(() -> tokenService.refreshToken(testToken, userPrincipal))
                .isInstanceOf(AuthenticationException.class)
                .hasMessageContaining("User is banned");
        
        // Verify token was blacklisted
        assertThat(tokenService.isTokenBlacklisted(testToken)).isTrue();
    }
    
    @Test
    @DisplayName("Should invalidate all user tokens")
    void testInvalidateUserTokens() {
        // When
        tokenService.invalidateUserTokens(testUserId);
        
        // Then
        // The tokenBlacklistService should have blacklisted a special token
        String userSpecificToken = "user_tokens_invalidated:" + testUserId.toString();
        assertThat(tokenBlacklistService.isBlacklisted(userSpecificToken)).isTrue();
        
        // Validate token should now return false
        assertThat(tokenService.validateToken(testToken, userPrincipal)).isFalse();
    }
    
    @Test
    @DisplayName("Should handle null when invalidating user tokens")
    void testInvalidateUserTokensWithNull() {
        // When
        tokenService.invalidateUserTokens(null);
        
        // Then
        // No exception should be thrown
        // Validate token should still work
        assertThat(tokenService.validateToken(testToken, userPrincipal)).isTrue();
    }
} 