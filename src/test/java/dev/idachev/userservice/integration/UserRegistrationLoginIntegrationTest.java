package dev.idachev.userservice.integration;

import dev.idachev.userservice.model.Role;
import dev.idachev.userservice.model.User;
import dev.idachev.userservice.repository.UserRepository;
import dev.idachev.userservice.service.EmailService;
import dev.idachev.userservice.service.TokenService;
import dev.idachev.userservice.web.dto.AuthResponse;
import dev.idachev.userservice.web.dto.RegisterRequest;
import dev.idachev.userservice.web.dto.SignInRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

/**
 * Integration tests for user registration and login
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
class UserRegistrationLoginIntegrationTest {
    // API endpoints
    private static final String API_REGISTER = "/api/v1/auth/signup";
    private static final String API_LOGIN = "/api/v1/auth/signin";

    // Test user credentials
    private static final String TEST_USERNAME = "testuser";
    private static final String TEST_EMAIL = "test@example.com";
    private static final String TEST_PASSWORD = "Password123!";

    // Test token
    private static final String TEST_TOKEN = "test.jwt.token";

    @Autowired
    private TestRestTemplate restTemplate;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @MockitoBean
    private EmailService emailService;

    @MockitoBean
    private TokenService tokenService;

    private final List<User> testUsers = new ArrayList<>();

    @BeforeEach
    void setUp() {
        // Mock email sending to avoid actual email dispatch
        when(emailService.sendVerificationEmailAsync(any(User.class)))
                .thenReturn(CompletableFuture.completedFuture(null));

        // Mock verification token generation
        when(emailService.generateVerificationToken()).thenReturn(UUID.randomUUID().toString());

        // Mock token generation to ensure we always have a non-null token
        when(tokenService.generateToken(any())).thenReturn(TEST_TOKEN);
    }

    @AfterEach
    void tearDown() {
        userRepository.deleteAll(testUsers);
        testUsers.clear();
    }

    /**
     * Helper method to create a test user
     */
    private User createUser(String username, String email, boolean verified) {
        User user = new User();
        user.setUsername(username);
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode(TEST_PASSWORD));
        user.setRole(Role.USER);
        user.setEnabled(verified);

        if (!verified) {
            user.setVerificationToken(UUID.randomUUID().toString());
        }

        user = userRepository.save(user);
        testUsers.add(user);
        return user;
    }

    @Test
    @DisplayName("Register new user successfully")
    void registerUser_validRequest_returnsCreatedUser() {
        // Given
        RegisterRequest request = new RegisterRequest(
                TEST_USERNAME, 
                TEST_EMAIL, 
                TEST_PASSWORD
        );

        // When
        ResponseEntity<AuthResponse> response = restTemplate.postForEntity(
                API_REGISTER, 
                request, 
                AuthResponse.class
        );

        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        assertThat(response.getBody()).isNotNull();

        // Check the direct fields in AuthResponse
        assertThat(response.getBody().getUsername()).isEqualTo(TEST_USERNAME);
        assertThat(response.getBody().getEmail()).isEqualTo(TEST_EMAIL);
        assertThat(response.getBody().getToken()).isNotBlank();
        assertThat(response.getBody().isSuccess()).isTrue();

        // Check the nested user object in AuthResponse
        assertThat(response.getBody().getUser()).isNotNull();
        assertThat(response.getBody().getUser().getUsername()).isEqualTo(TEST_USERNAME);
        assertThat(response.getBody().getUser().getEmail()).isEqualTo(TEST_EMAIL);

        // Verify user was created in database
        User createdUser = userRepository.findByUsername(TEST_USERNAME).orElse(null);
        assertThat(createdUser).isNotNull();
        assertThat(createdUser.isEnabled()).isFalse(); // User should be unverified initially
        assertThat(createdUser.getVerificationToken()).isNotBlank();

        // Add to test users for cleanup
        testUsers.add(createdUser);
    }

    @Test
    @DisplayName("Login with verified user credentials succeeds")
    void loginUser_verifiedUser_returnsToken() {
        // Given - Create verified user
        User verifiedUser = createUser("verifieduser", "verified@example.com", true);

        SignInRequest request = new SignInRequest(
                verifiedUser.getUsername(),
                TEST_PASSWORD
        );

        // When
        ResponseEntity<AuthResponse> response = restTemplate.postForEntity(
                API_LOGIN, 
                request, 
                AuthResponse.class
        );

        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();

        // Check direct fields in AuthResponse
        assertThat(response.getBody().getUsername()).isEqualTo(verifiedUser.getUsername());
        assertThat(response.getBody().getToken()).isNotBlank();
        assertThat(response.getBody().isSuccess()).isTrue();

        // Check nested user object
        assertThat(response.getBody().getUser()).isNotNull();
        assertThat(response.getBody().getUser().getUsername()).isEqualTo(verifiedUser.getUsername());
    }

    @Test
    @DisplayName("Login with unverified user credentials fails")
    void loginUser_unverifiedUser_returnsForbidden() {
        // Given - Create unverified user
        User unverifiedUser = createUser("unverifieduser", "unverified@example.com", false);

        SignInRequest request = new SignInRequest(
                unverifiedUser.getUsername(),
                TEST_PASSWORD
        );

        // When
        ResponseEntity<AuthResponse> response = restTemplate.postForEntity(
                API_LOGIN, 
                request, 
                AuthResponse.class
        );

        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    @DisplayName("Login with invalid credentials fails")
    void loginUser_invalidCredentials_returnsUnauthorized() {
        // Given - Create user
        User user = createUser("validuser", "valid@example.com", true);

        SignInRequest request = new SignInRequest(
                user.getUsername(),
                "WrongPassword123!"
        );

        // When
        ResponseEntity<AuthResponse> response = restTemplate.postForEntity(
                API_LOGIN, 
                request, 
                AuthResponse.class
        );

        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    @DisplayName("Login with non-existent user fails")
    void loginUser_nonExistentUser_returnsUnauthorized() {
        // Given
        SignInRequest request = new SignInRequest(
                "nonexistentuser",
                TEST_PASSWORD
        );

        // When
        ResponseEntity<AuthResponse> response = restTemplate.postForEntity(
                API_LOGIN, 
                request, 
                AuthResponse.class
        );

        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    @DisplayName("Register with duplicate username fails")
    void registerUser_duplicateUsername_returnsBadRequest() {
        // Given - Create existing user
        User existingUser = createUser(TEST_USERNAME, "existing@example.com", true);

        RegisterRequest request = new RegisterRequest(
                TEST_USERNAME, // Same username
                "new@example.com", 
                TEST_PASSWORD
        );

        // When
        ResponseEntity<AuthResponse> response = restTemplate.postForEntity(
                API_REGISTER, 
                request, 
                AuthResponse.class
        );

        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    @DisplayName("Register with duplicate email fails")
    void registerUser_duplicateEmail_returnsBadRequest() {
        // Given - Create existing user
        User existingUser = createUser("existinguser", TEST_EMAIL, true);

        RegisterRequest request = new RegisterRequest(
                "newuser", 
                TEST_EMAIL, // Same email
                TEST_PASSWORD
        );

        // When
        ResponseEntity<AuthResponse> response = restTemplate.postForEntity(
                API_REGISTER, 
                request, 
                AuthResponse.class
        );

        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }
} 
