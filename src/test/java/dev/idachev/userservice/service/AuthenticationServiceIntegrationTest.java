package dev.idachev.userservice.service;

import dev.idachev.userservice.config.BaseIntegrationTest;
import dev.idachev.userservice.config.TestDataInitializer;
import dev.idachev.userservice.exception.AuthenticationException;
import dev.idachev.userservice.exception.DuplicateUserException;
import dev.idachev.userservice.model.User;
import dev.idachev.userservice.repository.UserRepository;
import dev.idachev.userservice.web.dto.AuthResponse;
import dev.idachev.userservice.web.dto.GenericResponse;
import dev.idachev.userservice.web.dto.RegisterRequest;
import dev.idachev.userservice.web.dto.SignInRequest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.transaction.annotation.Transactional;

import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration tests for AuthenticationService.
 * Uses H2 in-memory database with test profile.
 */
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
class AuthenticationServiceIntegrationTest extends BaseIntegrationTest {

    @Autowired
    private AuthenticationService authenticationService;

    @Autowired
    private UserRepository userRepository;

    @Test
    @Transactional
    void register_WithValidData_CreatesNewUser() {
        // Given: Valid registration data
        RegisterRequest request = new RegisterRequest();
        request.setUsername("newuser123");
        request.setEmail("newuser123@example.com");
        request.setPassword("Password123!");

        // When: We register a new user
        AuthResponse response = authenticationService.register(request);

        // Then: User should be created with correct data
        assertNotNull(response);
        assertEquals("newuser123", response.getUsername());
        assertEquals("newuser123@example.com", response.getEmail());
        assertTrue(response.isSuccess());
        // Verify the user exists in the database
        assertTrue(userRepository.existsByUsername("newuser123"));
    }

    @Test
    @Transactional
    void register_WithExistingUsername_ThrowsException() {
        // Given: Registration data with existing username
        RegisterRequest request = new RegisterRequest();
        request.setUsername("admin"); // Username from TestDataInitializer
        request.setEmail("newuser@example.com");
        request.setPassword("Password123!");

        // When/Then: Registration should throw an exception
        assertThrows(DuplicateUserException.class, () -> 
            authenticationService.register(request));
    }

    @Test
    @Transactional
    void signIn_WithValidCredentials_ReturnsAuthResponse() {
        // Given: Valid sign-in credentials
        SignInRequest request = new SignInRequest();
        request.setIdentifier("admin");
        request.setPassword("Password123!");

        // When: We sign in
        AuthResponse response = authenticationService.signIn(request);

        // Then: Authentication should succeed
        assertNotNull(response);
        assertEquals("admin", response.getUsername());
        assertEquals("admin@example.com", response.getEmail());
        assertEquals("ADMIN", response.getRole());
        assertNotNull(response.getToken());
        assertTrue(response.isSuccess());
    }

    @Test
    @Transactional
    void signIn_WithInvalidPassword_ThrowsException() {
        // Given: Sign-in request with invalid password
        SignInRequest request = new SignInRequest();
        request.setIdentifier("admin");
        request.setPassword("WrongPassword123!");

        // When/Then: Authentication should fail
        assertThrows(BadCredentialsException.class, () -> 
            authenticationService.signIn(request));
    }

    @Test
    @Transactional
    void signIn_WithBannedUser_ThrowsException() {
        // Given: Sign-in request for banned user
        SignInRequest request = new SignInRequest();
        request.setIdentifier("banned");
        request.setPassword("Password123!");

        // When/Then: Authentication should fail with specific exception
        Exception exception = assertThrows(AuthenticationException.class, () -> 
            authenticationService.signIn(request));
        assertTrue(exception.getMessage().contains("banned"));
    }

    @Test
    @Transactional
    void signIn_WithUnverifiedUser_ThrowsException() {
        // Given: Sign-in request for unverified user
        SignInRequest request = new SignInRequest();
        request.setIdentifier("unverified");
        request.setPassword("Password123!");

        // When/Then: Authentication should fail with specific exception
        Exception exception = assertThrows(AuthenticationException.class, () -> 
            authenticationService.signIn(request));
        assertTrue(exception.getMessage().contains("not verified"));
    }

    @Test
    @Transactional
    void changeUsername_WithValidData_ChangesUsername() {
        // Given: Existing user with valid password
        String oldUsername = "user";
        String newUsername = "newusername123";
        String password = "Password123!";

        // When: We change the username
        GenericResponse response = authenticationService.changeUsername(oldUsername, newUsername, password);

        // Then: Username should be changed
        assertTrue(response.isSuccess());
        assertTrue(userRepository.existsByUsername(newUsername));
        assertFalse(userRepository.existsByUsername(oldUsername));
    }

    @Test
    @Transactional
    void changeUsername_WithIncorrectPassword_ThrowsException() {
        // Given: Existing user with invalid password
        String username = "user";
        String newUsername = "newusername";
        String wrongPassword = "WrongPassword123!";

        // When/Then: Username change should fail
        assertThrows(AuthenticationException.class, () -> 
            authenticationService.changeUsername(username, newUsername, wrongPassword));
    }

    @Test
    @Transactional
    void checkUserBanStatus_WithExistingUser_ReturnsCorrectStatus() {
        // Given: Known user identifiers
        String regularUser = "user";
        String bannedUser = "banned";

        // When: We check ban status
        Map<String, Object> regularUserStatus = authenticationService.checkUserBanStatus(regularUser);
        Map<String, Object> bannedUserStatus = authenticationService.checkUserBanStatus(bannedUser);

        // Then: The status should be correct
        assertFalse((Boolean) regularUserStatus.get("banned"));
        assertTrue((Boolean) bannedUserStatus.get("banned"));
    }

    @Test
    @Transactional
    void checkUserBanStatus_WithNonExistentUser_ReturnsFalse() {
        // Given: Non-existent user identifier
        String nonExistentUser = "nonexistentuser123";

        // When: We check ban status
        Map<String, Object> status = authenticationService.checkUserBanStatus(nonExistentUser);

        // Then: For security, even non-existent users return false (not banned)
        assertFalse((Boolean) status.get("banned"));
    }

    @Test
    @Transactional
    void findByUsernameOrEmail_WithExistingUsername_ReturnsUser() {
        // Given: Existing username
        String username = "admin";

        // When: We find the user
        User user = authenticationService.findByUsernameOrEmail(username);

        // Then: The correct user should be returned
        assertNotNull(user);
        assertEquals(username, user.getUsername());
        assertEquals("admin@example.com", user.getEmail());
    }

    @Test
    @Transactional
    void findByUsernameOrEmail_WithExistingEmail_ReturnsUser() {
        // Given: Existing email
        String email = "user@example.com";

        // When: We find the user
        User user = authenticationService.findByUsernameOrEmail(email);

        // Then: The correct user should be returned
        assertNotNull(user);
        assertEquals("user", user.getUsername());
        assertEquals(email, user.getEmail());
    }
} 