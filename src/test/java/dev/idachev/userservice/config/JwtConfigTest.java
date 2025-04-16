package dev.idachev.userservice.config;

import dev.idachev.userservice.model.Role;
import dev.idachev.userservice.model.User;
import dev.idachev.userservice.security.UserPrincipal;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.test.util.ReflectionTestUtils;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.within;

@ExtendWith(MockitoExtension.class)
class JwtConfigUTest {

    private JwtConfig jwtConfig;
    
    private User testUser;
    private UserPrincipal userPrincipal;
    private UUID userId;
    private String testSecret;
    private Long testExpiration;
    
    @BeforeEach
    void setUp() {
        jwtConfig = new JwtConfig();
        
        testSecret = "ThisIsATestSecretKeyUsedForJwtConfigurationTestingPurposes";
        testExpiration = 3600000L; // 1 hour
        
        ReflectionTestUtils.setField(jwtConfig, "secret", testSecret);
        ReflectionTestUtils.setField(jwtConfig, "expiration", testExpiration);
        
        jwtConfig.init(); // Initialize signing key
        
        userId = UUID.randomUUID();
        testUser = User.builder()
                .id(userId)
                .username("testuser")
                .email("test@example.com")
                .password("encodedPassword")
                .role(Role.USER)
                .enabled(true)
                .banned(false)
                .createdOn(LocalDateTime.now())
                .updatedOn(LocalDateTime.now())
                .build();
                
        userPrincipal = new UserPrincipal(testUser);
    }
    
    @Test
    @DisplayName("Should generate token successfully for user principal")
    void should_GenerateToken_ForUserPrincipal_Successfully() {
        // Given
        UserDetails userDetails = userPrincipal;
        
        // When
        String token = jwtConfig.generateToken(userDetails);
        
        // Then
        assertThat(token).isNotNull();
        
        Claims claims = extractClaims(token);
        assertThat(claims.getSubject()).isEqualTo(testUser.getUsername());
        assertThat(claims.get("userId", String.class)).isEqualTo(userId.toString());
        assertThat(claims.get("role", String.class)).isEqualTo(Role.USER.toString());
        assertThat(claims.get("email", String.class)).isEqualTo(testUser.getEmail());
        
        Date expiration = claims.getExpiration();
        Date issuedAt = claims.getIssuedAt();
        
        long now = System.currentTimeMillis();
        assertThat(issuedAt.getTime()).isCloseTo(now, within(1000L));
        assertThat(expiration.getTime()).isCloseTo(now + testExpiration, within(1000L));
    }
    
    @Test
    @DisplayName("Should extract username from token successfully")
    void should_ExtractUsername_FromToken_Successfully() {
        // Given
        String token = createTestToken(testUser.getUsername(), userId);
        
        // When
        String extractedUsername = jwtConfig.extractUsername(token);
        
        // Then
        assertThat(extractedUsername).isEqualTo(testUser.getUsername());
    }
    
    @Test
    @DisplayName("Should extract user ID from token successfully")
    void should_ExtractUserId_FromToken_Successfully() {
        // Given
        String token = createTestToken(testUser.getUsername(), userId);
        
        // When
        UUID extractedUserId = jwtConfig.extractUserId(token);
        
        // Then
        assertThat(extractedUserId).isEqualTo(userId);
    }
    
    @Test
    @DisplayName("Should extract expiration date from token successfully")
    void should_ExtractExpiration_FromToken_Successfully() {
        // Given
        Date expectedExpiration = new Date(System.currentTimeMillis() + testExpiration);
        String token = createTestTokenWithExpiration(testUser.getUsername(), userId, expectedExpiration);
        
        // When
        Date extractedExpiration = jwtConfig.extractExpiration(token);
        
        // Then
        assertThat(extractedExpiration.getTime()).isCloseTo(expectedExpiration.getTime(), within(1000L));
    }
    
    @Test
    @DisplayName("Should validate token successfully when token is valid")
    void should_ValidateToken_When_TokenIsValid() {
        // Given
        String token = createTestToken(testUser.getUsername(), userId);
        
        // When
        boolean isValid = jwtConfig.validateToken(token, userPrincipal);
        
        // Then
        assertThat(isValid).isTrue();
    }
    
    @Test
    @DisplayName("Should return false when validating token with wrong username")
    void should_ReturnFalse_When_ValidatingTokenWithWrongUsername() {
        // Given
        String token = createTestToken("wrongUsername", userId);
        
        // When
        boolean isValid = jwtConfig.validateToken(token, userPrincipal);
        
        // Then
        assertThat(isValid).isFalse();
    }
    
    @Test
    @DisplayName("Should return false when validating expired token")
    void should_ReturnFalse_When_ValidatingExpiredToken() {
        // Given
        Date pastDate = new Date(System.currentTimeMillis() - 1000);
        String token = createTestTokenWithExpiration(testUser.getUsername(), userId, pastDate);
        
        // When
        boolean isValid = jwtConfig.validateToken(token, userPrincipal);
        
        // Then
        assertThat(isValid).isFalse();
    }
    
    @Test
    @DisplayName("Should return false when validating token for disabled user")
    void should_ReturnFalse_When_ValidatingTokenForDisabledUser() {
        // Given
        String token = createTestToken(testUser.getUsername(), userId);
        
        User disabledUser = User.builder()
                .id(userId)
                .username(testUser.getUsername())
                .email(testUser.getEmail())
                .enabled(false)
                .build();
        UserPrincipal disabledUserPrincipal = new UserPrincipal(disabledUser);
        
        // When
        boolean isValid = jwtConfig.validateToken(token, disabledUserPrincipal);
        
        // Then
        assertThat(isValid).isFalse();
    }
    
    @Test
    @DisplayName("Should detect expired token correctly")
    void should_DetectExpiredToken_Correctly() {
        // Given
        Date pastDate = new Date(System.currentTimeMillis() - 1000);
        String expiredToken = createTestTokenWithExpiration(testUser.getUsername(), userId, pastDate);
        
        // When
        boolean isExpired = jwtConfig.isTokenExpired(expiredToken);
        
        // Then
        assertThat(isExpired).isTrue();
    }
    
    private String createTestToken(String username, UUID userId) {
        Key signingKey = Keys.hmacShaKeyFor(testSecret.getBytes(StandardCharsets.UTF_8));
        
        return Jwts.builder()
                .setSubject(username)
                .claim("userId", userId.toString())
                .claim("role", Role.USER.toString())
                .claim("email", testUser.getEmail())
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + testExpiration))
                .signWith(signingKey, SignatureAlgorithm.HS384)
                .compact();
    }
    
    private String createTestTokenWithExpiration(String username, UUID userId, Date expiration) {
        Key signingKey = Keys.hmacShaKeyFor(testSecret.getBytes(StandardCharsets.UTF_8));
        
        return Jwts.builder()
                .setSubject(username)
                .claim("userId", userId.toString())
                .claim("role", Role.USER.toString())
                .claim("email", testUser.getEmail())
                .setIssuedAt(new Date())
                .setExpiration(expiration)
                .signWith(signingKey, SignatureAlgorithm.HS384)
                .compact();
    }
    
    private Claims extractClaims(String token) {
        Key signingKey = Keys.hmacShaKeyFor(testSecret.getBytes(StandardCharsets.UTF_8));
        
        return Jwts.parserBuilder()
                .setSigningKey(signingKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
} 