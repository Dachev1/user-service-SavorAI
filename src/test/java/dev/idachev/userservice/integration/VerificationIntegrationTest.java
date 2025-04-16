package dev.idachev.userservice.integration;

import dev.idachev.userservice.model.Role;
import dev.idachev.userservice.model.User;
import dev.idachev.userservice.repository.UserRepository;
import dev.idachev.userservice.service.EmailService;
import dev.idachev.userservice.web.dto.AuthResponse;
import dev.idachev.userservice.web.dto.GenericResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doNothing;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
class VerificationIntegrationTest {

    @Autowired
    private TestRestTemplate restTemplate;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @MockBean
    private EmailService emailService;

    private User unverifiedUser;
    private User verifiedUser;

    @BeforeEach
    void setUp() {
        // Mock email sending to avoid actual email dispatch
        doNothing().when(emailService).sendVerificationEmailAsync(any(User.class));

        // Create an unverified user
        unverifiedUser = new User();
        unverifiedUser.setUsername("unverified");
        unverifiedUser.setEmail("unverified@example.com");
        unverifiedUser.setPassword(passwordEncoder.encode("Password123!"));
        unverifiedUser.setRole(Role.USER);
        unverifiedUser.setEnabled(false);
        unverifiedUser.setVerificationToken(UUID.randomUUID().toString());
        unverifiedUser = userRepository.save(unverifiedUser);

        // Create a verified user
        verifiedUser = new User();
        verifiedUser.setUsername("verified");
        verifiedUser.setEmail("verified@example.com");
        verifiedUser.setPassword(passwordEncoder.encode("Password123!"));
        verifiedUser.setRole(Role.USER);
        verifiedUser.setEnabled(true);
        verifiedUser.setVerificationToken(null);
        verifiedUser = userRepository.save(verifiedUser);
    }

    @AfterEach
    void tearDown() {
        userRepository.deleteAll();
    }

    @Test
    @DisplayName("Should return verification status for unverified user")
    void should_ReturnVerificationStatus_ForUnverifiedUser() {
        // When
        String url = UriComponentsBuilder.fromPath("/api/v1/verification/status")
                .queryParam("email", unverifiedUser.getEmail())
                .toUriString();
        ResponseEntity<AuthResponse> response = restTemplate.getForEntity(url, AuthResponse.class);

        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().getUser()).isNotNull();
        assertThat(response.getBody().getUser().getEmail()).isEqualTo(unverifiedUser.getEmail());
        assertThat(response.getBody().isVerified()).isFalse();
        assertThat(response.getBody().getToken()).isNull();
    }

    @Test
    @DisplayName("Should return verification status for verified user")
    void should_ReturnVerificationStatus_ForVerifiedUser() {
        // When
        String url = UriComponentsBuilder.fromPath("/api/v1/verification/status")
                .queryParam("email", verifiedUser.getEmail())
                .toUriString();
        ResponseEntity<AuthResponse> response = restTemplate.getForEntity(url, AuthResponse.class);

        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().getUser()).isNotNull();
        assertThat(response.getBody().getUser().getEmail()).isEqualTo(verifiedUser.getEmail());
        assertThat(response.getBody().isVerified()).isTrue();
    }

    @Test
    @DisplayName("Should resend verification email successfully")
    void should_ResendVerificationEmail_Successfully() {
        // When
        String url = UriComponentsBuilder.fromPath("/api/v1/verification/resend")
                .queryParam("email", unverifiedUser.getEmail())
                .toUriString();
        ResponseEntity<GenericResponse> response = restTemplate.postForEntity(url, null, GenericResponse.class);

        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().isSuccess()).isTrue();
        assertThat(response.getBody().getMessage()).contains("resent");

        // Verify token was updated
        User updatedUser = userRepository.findById(unverifiedUser.getId()).orElseThrow();
        assertThat(updatedUser.getVerificationToken()).isNotNull();
        assertThat(updatedUser.getVerificationToken()).isNotEqualTo(unverifiedUser.getVerificationToken());
    }

    @Test
    @DisplayName("Should not resend verification email for already verified user")
    void should_NotResendVerificationEmail_ForAlreadyVerifiedUser() {
        // When
        String url = UriComponentsBuilder.fromPath("/api/v1/verification/resend")
                .queryParam("email", verifiedUser.getEmail())
                .toUriString();
        ResponseEntity<GenericResponse> response = restTemplate.postForEntity(url, null, GenericResponse.class);

        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().isSuccess()).isFalse();
        assertThat(response.getBody().getMessage()).contains("already verified");
    }

    @Test
    @DisplayName("Should verify user with valid token")
    void should_VerifyUser_WithValidToken() {
        // When
        String url = UriComponentsBuilder.fromPath("/api/v1/verification/verify/{token}")
                .buildAndExpand(unverifiedUser.getVerificationToken())
                .toUriString();
        ResponseEntity<Object> response = restTemplate.getForEntity(url, Object.class);

        // Then
        // The endpoint redirects to frontend, so we expect a 3xx status
        assertThat(response.getStatusCode().is3xxRedirection()).isTrue();

        // Verify the user is now enabled and token is cleared
        User updatedUser = userRepository.findById(unverifiedUser.getId()).orElseThrow();
        assertThat(updatedUser.isEnabled()).isTrue();
        assertThat(updatedUser.getVerificationToken()).isNull();
    }

    @Test
    @DisplayName("Should fail verification with invalid token")
    void should_FailVerification_WithInvalidToken() {
        // When
        String url = UriComponentsBuilder.fromPath("/api/v1/verification/verify/{token}")
                .buildAndExpand("invalid-token")
                .toUriString();
        ResponseEntity<Object> response = restTemplate.getForEntity(url, Object.class);

        // Then
        assertThat(response.getStatusCode().is3xxRedirection()).isTrue();

        // User should still be unverified
        User updatedUser = userRepository.findById(unverifiedUser.getId()).orElseThrow();
        assertThat(updatedUser.isEnabled()).isFalse();
        assertThat(updatedUser.getVerificationToken()).isNotNull();
    }
} 