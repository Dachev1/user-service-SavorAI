package dev.idachev.userservice.service;

import dev.idachev.userservice.config.BaseIntegrationTest;
import dev.idachev.userservice.config.TestDataInitializer;
import dev.idachev.userservice.model.User;
import dev.idachev.userservice.repository.UserRepository;
import dev.idachev.userservice.security.UserPrincipal;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration tests for TokenService.
 * Uses H2 in-memory database with test profile.
 */
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
class TokenServiceIntegrationTest extends BaseIntegrationTest {

    @Autowired
    private TokenService tokenService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private UserDetailsService userDetailsService;

    @Test
    @Transactional
    void generateToken_ReturnsValidToken() {
        // Given: A known user
        User user = userRepository.findById(TestDataInitializer.REGULAR_USER_ID).orElseThrow();
        UserDetails userDetails = new UserPrincipal(user);

        // When: We generate a token
        String token = tokenService.generateToken(userDetails);

        // Then: Token should be valid
        assertNotNull(token);
        assertTrue(token.length() > 20);  // Token should be a reasonably long string
        assertTrue(tokenService.validateToken(token, userDetails));
    }

    @Test
    @Transactional
    void validateToken_WithValidToken_ReturnsTrue() {
        // Given: A known user and a generated token
        User user = userRepository.findById(TestDataInitializer.REGULAR_USER_ID).orElseThrow();
        UserDetails userDetails = new UserPrincipal(user);
        String token = tokenService.generateToken(userDetails);

        // When: We validate the token
        boolean isValid = tokenService.validateToken(token, userDetails);

        // Then: Token should be valid
        assertTrue(isValid);
    }

    @Test
    @Transactional
    void extractUserId_ReturnsCorrectUserId() {
        // Given: A known user and a generated token
        UUID expectedUserId = TestDataInitializer.REGULAR_USER_ID;
        User user = userRepository.findById(expectedUserId).orElseThrow();
        UserDetails userDetails = new UserPrincipal(user);
        String token = tokenService.generateToken(userDetails);

        // When: We extract the user ID
        UUID extractedUserId = tokenService.extractUserId(token);

        // Then: User ID should match
        assertEquals(expectedUserId, extractedUserId);
    }

    @Test
    @Transactional
    void extractUsername_ReturnsCorrectUsername() {
        // Given: A known user and a generated token
        User user = userRepository.findById(TestDataInitializer.REGULAR_USER_ID).orElseThrow();
        String expectedUsername = user.getUsername();
        UserDetails userDetails = new UserPrincipal(user);
        String token = tokenService.generateToken(userDetails);

        // When: We extract the username
        String extractedUsername = tokenService.extractUsername(token);

        // Then: Username should match
        assertEquals(expectedUsername, extractedUsername);
    }

    @Test
    @Transactional
    void blacklistToken_AndValidate_ReturnsFalse() {
        // Given: A known user and a generated token
        User user = userRepository.findById(TestDataInitializer.REGULAR_USER_ID).orElseThrow();
        UserDetails userDetails = new UserPrincipal(user);
        String token = tokenService.generateToken(userDetails);
        String authHeader = "Bearer " + token;

        // When: We blacklist the token
        boolean blacklisted = tokenService.blacklistToken(authHeader);

        // Then: Token should be blacklisted and no longer valid
        assertTrue(blacklisted);
        assertTrue(tokenService.isTokenBlacklisted(token));
        assertFalse(tokenService.validateToken(token, userDetails));
    }

    @Test
    @Transactional
    void invalidateUserTokens_MakesTokensInvalid() {
        // Given: A known user and a generated token
        UUID userId = TestDataInitializer.REGULAR_USER_ID;
        User user = userRepository.findById(userId).orElseThrow();
        UserDetails userDetails = new UserPrincipal(user);
        String token = tokenService.generateToken(userDetails);

        // Verify token is initially valid
        assertTrue(tokenService.validateToken(token, userDetails));

        // When: We invalidate all tokens for the user
        tokenService.invalidateUserTokens(userId);

        // Then: The token should no longer be valid
        assertFalse(tokenService.validateToken(token, userDetails));
        assertTrue(tokenService.isTokenBlacklisted(token));
    }
} 