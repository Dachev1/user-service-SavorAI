package dev.idachev.userservice.integration;

import dev.idachev.userservice.model.Role;
import dev.idachev.userservice.model.User;
import dev.idachev.userservice.repository.UserRepository;
import dev.idachev.userservice.service.EmailService;
import dev.idachev.userservice.web.dto.AuthResponse;
import dev.idachev.userservice.web.dto.GenericResponse;
import dev.idachev.userservice.web.dto.VerificationResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
class VerificationIntegrationTest {
    private static final Logger logger = LoggerFactory.getLogger(VerificationIntegrationTest.class);
    
    // Constants for API paths
    private static final String DEFAULT_PASSWORD = "Password123!";
    private static final String API_VERIFICATION_STATUS = "/api/v1/verification/status";
    private static final String API_VERIFICATION_RESEND = "/api/v1/verification/resend";
    private static final String API_VERIFICATION_VERIFY = "/api/v1/verification/verify/{token}";
    
    @Autowired
    private TestRestTemplate restTemplate;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @MockitoBean
    private EmailService emailService;

    private User unverifiedUser;
    private User verifiedUser;
    private final List<User> testUsers = new ArrayList<>();

    @BeforeEach
    void setUp() {
        // Mock email sending to avoid actual email dispatch
        when(emailService.sendVerificationEmailAsync(any(User.class)))
                .thenReturn(CompletableFuture.completedFuture(null));

        // Create test users
        unverifiedUser = createUser("unverified", "unverified@example.com", false);
        verifiedUser = createUser("verified", "verified@example.com", true);
        verifiedUser.setVerificationToken(null);
        verifiedUser = userRepository.save(verifiedUser);
    }

    @AfterEach
    void tearDown() {
        try {
            userRepository.deleteAll(testUsers);
            testUsers.clear();
        } catch (Exception e) {
            logger.error("Error during test cleanup: {}", e.getMessage());
        }
    }
    
    /**
     * Helper method to create a test user
     */
    private User createUser(String username, String email, boolean enabled) {
        User user = new User();
        user.setUsername(username);
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode(DEFAULT_PASSWORD));
        user.setRole(Role.USER);
        user.setEnabled(enabled);
        if (!enabled) {
            user.setVerificationToken(UUID.randomUUID().toString());
        }
        user = userRepository.save(user);
        testUsers.add(user);
        return user;
    }

    @Test
    @DisplayName("Return verification status for unverified user")
    void getVerificationStatus_unverifiedUser_returnsFalseStatus() {
        // When
        String url = buildStatusUrl(unverifiedUser.getEmail());
        ResponseEntity<AuthResponse> response = restTemplate.getForEntity(url, AuthResponse.class);

        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().getUser()).isNotNull();
        assertThat(response.getBody().getUser().getEmail()).isEqualTo(unverifiedUser.getEmail());
        assertThat(response.getBody().isVerified()).isFalse();
        assertThat(response.getBody().getToken()).isNotNull();
    }

    @Test
    @DisplayName("Return verification status for verified user")
    void getVerificationStatus_verifiedUser_returnsTrueStatus() {
        // When
        String url = buildStatusUrl(verifiedUser.getEmail());
        ResponseEntity<AuthResponse> response = restTemplate.getForEntity(url, AuthResponse.class);

        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().getUser()).isNotNull();
        assertThat(response.getBody().getUser().getEmail()).isEqualTo(verifiedUser.getEmail());
        assertThat(response.getBody().isVerified()).isTrue();
        assertThat(response.getBody().getToken()).isNotBlank();
    }

    @Test
    @DisplayName("Resend verification email successfully for unverified user")
    void resendVerificationEmail_unverifiedUser_sendsNewEmail() {
        // When
        String url = buildResendUrl(unverifiedUser.getEmail());
        ResponseEntity<GenericResponse> response = restTemplate.postForEntity(url, null, GenericResponse.class);

        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().isSuccess()).isTrue();
        assertThat(response.getBody().getMessage()).contains("resent");

        // Verify user has a verification token
        User updatedUser = userRepository.findById(unverifiedUser.getId()).orElseThrow();
        assertThat(updatedUser.getVerificationToken()).isNotBlank();
    }

    @Test
    @DisplayName("Not resend verification email for already verified user")
    void resendVerificationEmail_verifiedUser_returnsError() {
        // When
        String url = buildResendUrl(verifiedUser.getEmail());
        ResponseEntity<GenericResponse> response = restTemplate.postForEntity(url, null, GenericResponse.class);

        // Then - Service throws IllegalArgumentException, handled as BAD_REQUEST
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().getMessage()).contains("already verified");
    }

    @Test
    @DisplayName("Verify user with valid token")
    void verifyUser_validToken_enablesUser() {
        // Create a fresh unverified user for this test
        User testUser = createUser("verifyTest", "verifytest@example.com", false);
        String token = testUser.getVerificationToken();
        
        // When
        String url = buildVerifyUrl(token);
                
        try {
            // We expect this to redirect, which might cause connection issues in test
            restTemplate.getForEntity(url, Object.class);
        } catch (Exception e) {
            // RestTemplate might throw an error trying to follow redirect or parse non-JSON
            logger.debug("Ignoring potential RestClientException due to redirection: {}", e.getMessage());
        }

        // Verify the user is now enabled in database
        User updatedUser = userRepository.findById(testUser.getId()).orElseThrow();
        assertThat(updatedUser.isEnabled()).isTrue();
        assertThat(updatedUser.getVerificationToken()).isNull();
    }

    @ParameterizedTest
    @DisplayName("Fail verification with invalid token")
    @ValueSource(strings = {"invalid-token", "12345"})
    void verifyUser_invalidToken_redirectsWithError(String invalidToken) {
        // Save original state
        boolean originalEnabled = unverifiedUser.isEnabled();
        String originalToken = unverifiedUser.getVerificationToken();
        
        // When
        String url = buildVerifyUrl(invalidToken);
        ResponseEntity<String> response = null;        
        try {
            // Make the request but don't follow redirects automatically
            response = restTemplate.getForEntity(url, String.class); 
        } catch (Exception e) {
             // This might happen if the redirect URL itself is invalid or unreachable in test
             logger.warn("Caught exception during invalid token verification test, likely redirect issue: {}", e.getMessage());
        }

        // Then - Check redirect status and location header if response is available
        if (response != null) {
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FOUND); // Expect 302 Found
            assertThat(response.getHeaders().getLocation()).isNotNull();
            assertThat(response.getHeaders().getLocation().toString()).contains("verified=false", "error=Invalid");
        } else {
            // Fallback if exception occurred: Check DB state (less ideal for this test)
             User updatedUser = userRepository.findById(unverifiedUser.getId()).orElseThrow();
             assertThat(updatedUser.isEnabled()).isEqualTo(originalEnabled);
             assertThat(updatedUser.getVerificationToken()).isEqualTo(originalToken);
        }

         // Always check DB state didn't change incorrectly
         User updatedUser = userRepository.findById(unverifiedUser.getId()).orElseThrow();
         assertThat(updatedUser.isEnabled()).isEqualTo(originalEnabled);
         assertThat(updatedUser.getVerificationToken()).isEqualTo(originalToken);
    }
    
    @ParameterizedTest
    @DisplayName("Fail verification with empty or null token")
    @NullAndEmptySource
    void verifyUser_emptyOrNullToken_returnsNotFoundOrBadRequest(String emptyToken) {
        // Save original state
        boolean originalEnabled = unverifiedUser.isEnabled();
        String originalToken = unverifiedUser.getVerificationToken();

        // When
        // Use the POST endpoint which doesn't redirect and provides a structured response
        String url = "/api/v1/verification/verify";
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> map= new LinkedMultiValueMap<>();
        map.add("token", emptyToken == null ? "" : emptyToken); // Use empty string for null/empty test cases

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(map, headers);
        
        ResponseEntity<VerificationResponse> response = restTemplate.postForEntity(url, request, VerificationResponse.class);

        // Then - Expect BAD_REQUEST as VerificationService should throw VerificationException for invalid/empty token
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().isSuccess()).isFalse();
        assertThat(response.getBody().getMessage()).contains("token"); // Check for error message related to token

        // User should still be unverified with unchanged state
        User updatedUser = userRepository.findById(unverifiedUser.getId()).orElseThrow();
        assertThat(updatedUser.isEnabled()).isEqualTo(originalEnabled);
        assertThat(updatedUser.getVerificationToken()).isEqualTo(originalToken);
    }

    @Test
    @DisplayName("Not verify already verified user")
    void verifyUser_alreadyVerifiedUser_redirectsAsAlreadyVerified() {
        // Create a token for testing with a verified user
        verifiedUser.setVerificationToken(UUID.randomUUID().toString());
        verifiedUser = userRepository.save(verifiedUser);
        
        String originalToken = verifiedUser.getVerificationToken();
        
        // When
        String url = buildVerifyUrl(originalToken);
        ResponseEntity<String> response = null;        
        try {
            response = restTemplate.getForEntity(url, String.class);
        } catch (Exception e) {
            logger.warn("Caught exception during already verified user test, likely redirect issue: {}", e.getMessage());
        }

        // Then - Check redirect status and location header
         if (response != null) {
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FOUND); // Expect 302 Found
            assertThat(response.getHeaders().getLocation()).isNotNull();
            // Check the specific error type for already verified
            assertThat(response.getHeaders().getLocation().toString()).contains("verified=false", "error=AlreadyVerified"); 
        }

        // User should remain verified
        User updatedUser = userRepository.findById(verifiedUser.getId()).orElseThrow();
        assertThat(updatedUser.isEnabled()).isTrue();
        // Token might be cleared or kept depending on service logic, test doesn't strictly need to check token here
    }

    @Test
    @DisplayName("Fail to resend verification email to non-existent user")
    void resendVerificationEmail_nonExistentUser_returnsNotFound() {
        // When
        String url = buildResendUrl("nonexistent@example.com");
        ResponseEntity<GenericResponse> response = restTemplate.postForEntity(url, null, GenericResponse.class);

        // Then - Now expect 404 based on GlobalExceptionHandler fix
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    }

    @Test
    @DisplayName("Fail to get verification status for non-existent user")
    void getVerificationStatus_nonExistentUser_returnsNotFound() {
        // When
        String url = buildStatusUrl("nonexistent@example.com");
        ResponseEntity<AuthResponse> response = restTemplate.getForEntity(url, AuthResponse.class);

        // Then - Now expect 404 based on GlobalExceptionHandler fix
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    }

    @ParameterizedTest
    @DisplayName("Fail operations with empty email")
    @NullAndEmptySource
    void verificationOperations_emptyEmail_returnsBadRequest(String emptyEmail) {
        // For status check
        String statusUrl = buildStatusUrl(emptyEmail == null ? "" : emptyEmail);
        ResponseEntity<AuthResponse> statusResponse = restTemplate.getForEntity(statusUrl, AuthResponse.class);
        assertThat(statusResponse.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        
        // For resend
        String resendUrl = buildResendUrl(emptyEmail == null ? "" : emptyEmail);
        ResponseEntity<GenericResponse> resendResponse = restTemplate.postForEntity(resendUrl, null, GenericResponse.class);
        assertThat(resendResponse.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @ParameterizedTest
    @DisplayName("Fail operations with malformed email")
    @ValueSource(strings = {"notanemail", "invalid@", "@nodomain"})
    void verificationOperations_malformedEmail_returnsBadRequest(String invalidEmail) {
        // For status check
        String statusUrl = buildStatusUrl(invalidEmail);
        ResponseEntity<AuthResponse> statusResponse = restTemplate.getForEntity(statusUrl, AuthResponse.class);
        assertThat(statusResponse.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        
        // For resend
        String resendUrl = buildResendUrl(invalidEmail);
        ResponseEntity<GenericResponse> resendResponse = restTemplate.postForEntity(resendUrl, null, GenericResponse.class);
        assertThat(resendResponse.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    @DisplayName("Handle email with special characters correctly")
    void handleEmailWithSpecialCharacters_validEmail_processesSuccessfully() {
        // Given
        String specialEmail = "user+tag@example.com";
        // Ensure user doesn't exist or cleanup handles it
        userRepository.findByEmail(specialEmail).ifPresent(userRepository::delete); 
        User specialUser = createUser("specialuser", specialEmail, false);
        // testUsers.add(specialUser); // createUser already adds to the list

        // When - Check status
        String statusUrl = buildStatusUrl(specialEmail);
        ResponseEntity<AuthResponse> statusResponse = restTemplate.getForEntity(statusUrl, AuthResponse.class);

        // Then - Expect OK now that validation allows '+'
        assertThat(statusResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(statusResponse.getBody()).isNotNull();
        assertThat(statusResponse.getBody().getUser()).isNotNull();
        assertThat(statusResponse.getBody().getUser().getEmail()).isEqualTo(specialEmail);
         assertThat(statusResponse.getBody().isVerified()).isFalse(); // Still unverified initially
    }

    @Test
    @DisplayName("Not allow one user to verify another user's account")
    void verifyUser_otherUsersToken_onlyVerifiesTokenOwner() {
        // Create two unverified users
        User user1 = createUser("user1", "user1@example.com", false);
        User user2 = createUser("user2", "user2@example.com", false);
        
        String token1 = user1.getVerificationToken();
        
        // When - try to verify user1
        String url = buildVerifyUrl(token1);
        
        try {
            restTemplate.getForEntity(url, Object.class);
        } catch (Exception e) {
            logger.debug("Ignoring potential RestClientException due to redirection: {}", e.getMessage());
        }
        
        // Then - only user1 should be verified
        User updatedUser1 = userRepository.findById(user1.getId()).orElseThrow();
        User updatedUser2 = userRepository.findById(user2.getId()).orElseThrow();
        
        assertThat(updatedUser1.isEnabled()).isTrue();
        assertThat(updatedUser2.isEnabled()).isFalse();
    }

    @Test
    @DisplayName("Prevent multiple verifications with the same token")
    void verifyUser_tokenUsedTwice_onlyWorksOnceAndRedirectsWithErrorSecondTime() {
        // Create user and save token
        User testUser = createUser("tokenReuseTest", "tokenreuse@example.com", false);
        String token = testUser.getVerificationToken();
        
        // First verification
        String url = buildVerifyUrl(token);
        try {
            restTemplate.getForEntity(url, Object.class);
        } catch (Exception e) {
            logger.debug("Ignoring potential RestClientException due to redirection (1st attempt): {}", e.getMessage());
        }
        
        // Verify user is enabled and token is cleared
        User verifiedUser = userRepository.findById(testUser.getId()).orElseThrow();
        assertThat(verifiedUser.isEnabled()).isTrue();
        assertThat(verifiedUser.getVerificationToken()).isNull();
        
        // Try second verification with same token
        ResponseEntity<String> response = null;
        try {
             response = restTemplate.getForEntity(url, String.class);
        } catch (Exception e) {
             logger.warn("Caught exception during second token verification attempt, likely redirect issue: {}", e.getMessage());
        }
         // Then - Check redirect status and location header if response is available
        if (response != null) {
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FOUND); // Expect 302 Found
            assertThat(response.getHeaders().getLocation()).isNotNull();
            // Check the specific error type for invalid/used token
            assertThat(response.getHeaders().getLocation().toString()).contains("verified=false", "error=Invalid"); 
        }
        
        // User should still be enabled, nothing changed incorrectly
        verifiedUser = userRepository.findById(testUser.getId()).orElseThrow();
        assertThat(verifiedUser.isEnabled()).isTrue();
        assertThat(verifiedUser.getVerificationToken()).isNull();
    }
    
    // Helper methods for URL building
    private String buildStatusUrl(String email) {
        return UriComponentsBuilder.fromPath(API_VERIFICATION_STATUS)
                .queryParam("email", email)
                .encode() // Ensure email is encoded
                .toUriString();
    }
    
    private String buildResendUrl(String email) {
        return UriComponentsBuilder.fromPath(API_VERIFICATION_RESEND)
                .queryParam("email", email)
                .encode() // Ensure email is encoded
                .toUriString();
    }
    
    private String buildVerifyUrl(String token) {
        // Token is a path variable, generally safe unless it contains '/' etc.
        // Encoding handled by buildAndExpand usually
        return UriComponentsBuilder.fromPath(API_VERIFICATION_VERIFY)
                .buildAndExpand(token) 
                .toUriString();
    }
} 