package dev.idachev.userservice.integration;

import dev.idachev.userservice.model.Role;
import dev.idachev.userservice.model.User;
import dev.idachev.userservice.repository.UserRepository;
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
import org.springframework.transaction.annotation.Transactional;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
class UserRegistrationLoginIntegrationTest {

    @Autowired
    private TestRestTemplate restTemplate;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    private RegisterRequest registerRequest;
    private SignInRequest signInRequest;
    private User existingUser;

    @BeforeEach
    @Transactional
    void setUp() {
        // Create test requests for registration and login
        registerRequest = new RegisterRequest(
                "newuser",
                "new@example.com",
                "Password123!"
        );
        
        signInRequest = new SignInRequest(
                "existinguser",
                "Password123!"
        );

        // Create and save a test user for login tests
        existingUser = new User();
        existingUser.setUsername("existinguser");
        existingUser.setEmail("existing@example.com");
        existingUser.setPassword(passwordEncoder.encode("Password123!"));
        existingUser.setRole(Role.USER);
        existingUser.setEnabled(true);
        existingUser.setBanned(false);

        // Save and capture the entity with its DB-generated ID
        existingUser = userRepository.save(existingUser);
    }

    @AfterEach
    void tearDown() {
        // Clean up test data
        userRepository.deleteAll();
    }

    @Test
    @DisplayName("Should register a new user successfully")
    void should_RegisterNewUser_Successfully() {
        // When
        ResponseEntity<AuthResponse> response = restTemplate.postForEntity(
                "/api/v1/auth/signup",
                registerRequest,
                AuthResponse.class
        );

        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().getToken()).isNotNull();
        assertThat(response.getBody().getUser()).isNotNull();
        assertThat(response.getBody().getUser().getUsername()).isEqualTo(registerRequest.getUsername());
        assertThat(response.getBody().getUser().getEmail()).isEqualTo(registerRequest.getEmail());

        // Verify user is saved in the database
        User savedUser = userRepository.findByUsername(registerRequest.getUsername()).orElse(null);
        assertThat(savedUser).isNotNull();
        assertThat(savedUser.getUsername()).isEqualTo(registerRequest.getUsername());
        assertThat(savedUser.getEmail()).isEqualTo(registerRequest.getEmail());
    }

    @Test
    @DisplayName("Should authenticate existing user successfully")
    void should_AuthenticateExistingUser_Successfully() {
        // When
        ResponseEntity<AuthResponse> response = restTemplate.postForEntity(
                "/api/v1/auth/signin",
                signInRequest,
                AuthResponse.class
        );

        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().getToken()).isNotNull();
        assertThat(response.getBody().getUser()).isNotNull();
        assertThat(response.getBody().getUser().getUsername()).isEqualTo(existingUser.getUsername());
    }

    @Test
    @DisplayName("Should reject registration with duplicate username")
    void should_RejectRegistration_WithDuplicateUsername() {
        // Given
        RegisterRequest duplicateRequest = new RegisterRequest(
                existingUser.getUsername(),
                "another@example.com",
                "Password123!"
        );

        // When
        ResponseEntity<Object> response = restTemplate.postForEntity(
                "/api/v1/auth/signup",
                duplicateRequest,
                Object.class
        );

        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
    }

    @Test
    @DisplayName("Should reject registration with duplicate email")
    void should_RejectRegistration_WithDuplicateEmail() {
        // Given
        RegisterRequest duplicateRequest = new RegisterRequest(
                "anotheruser",
                existingUser.getEmail(),
                "Password123!"
        );

        // When
        ResponseEntity<Object> response = restTemplate.postForEntity(
                "/api/v1/auth/signup",
                duplicateRequest,
                Object.class
        );

        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
    }

    @Test
    @DisplayName("Should reject authentication with invalid credentials")
    void should_RejectAuthentication_WithInvalidCredentials() {
        // Given
        SignInRequest invalidRequest = new SignInRequest(
                existingUser.getUsername(),
                "WrongPassword!"
        );

        // When
        ResponseEntity<Object> response = restTemplate.postForEntity(
                "/api/v1/auth/signin",
                invalidRequest,
                Object.class
        );

        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }
} 