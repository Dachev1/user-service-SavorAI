package dev.idachev.userservice.service;

import dev.idachev.userservice.config.BaseIntegrationTest;
import dev.idachev.userservice.config.TestDataInitializer;
import dev.idachev.userservice.exception.ResourceNotFoundException;
import dev.idachev.userservice.model.User;
import dev.idachev.userservice.repository.UserRepository;
import dev.idachev.userservice.web.dto.AuthResponse;
import dev.idachev.userservice.web.dto.GenericResponse;
import dev.idachev.userservice.web.dto.VerificationResponse;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.transaction.annotation.Transactional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration tests for VerificationService.
 * Uses H2 in-memory database with test profile.
 */
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
class VerificationServiceIntegrationTest extends BaseIntegrationTest {

    @Autowired
    private VerificationService verificationService;

    @Autowired
    private UserRepository userRepository;

    @Test
    @Transactional
    void getVerificationStatus_ForVerifiedUser_ReturnsTokenAndVerifiedStatus() {
        // Given: A known verified user
        String email = "user@example.com";

        // When: We get the verification status
        AuthResponse response = verificationService.getVerificationStatus(email);

        // Then: Response should indicate user is verified and include token
        assertNotNull(response);
        assertEquals(email, response.getEmail());
        assertTrue(response.isVerified());
        assertNotNull(response.getToken());
        assertFalse(response.getToken().isEmpty());
    }

    @Test
    @Transactional
    void getVerificationStatus_ForUnverifiedUser_ReturnsEmptyTokenAndUnverifiedStatus() {
        // Given: A known unverified user
        String email = "unverified@example.com";

        // When: We get the verification status
        AuthResponse response = verificationService.getVerificationStatus(email);

        // Then: Response should indicate user is not verified and token is empty
        assertNotNull(response);
        assertEquals(email, response.getEmail());
        assertFalse(response.isVerified());
        assertEquals("", response.getToken());
    }

    @Test
    @Transactional
    void verifyEmail_WithValidToken_VerifiesUser() {
        // Given: A known unverified user with verification token
        User unverifiedUser = userRepository.findById(TestDataInitializer.UNVERIFIED_USER_ID).orElseThrow();
        String token = unverifiedUser.getVerificationToken();
        assertNotNull(token);
        assertFalse(unverifiedUser.isEnabled());

        // When: We verify the email
        boolean verified = verificationService.verifyEmail(token);

        // Then: User should be verified
        assertTrue(verified);
        
        // Refresh user from database to see changes
        User verifiedUser = userRepository.findById(TestDataInitializer.UNVERIFIED_USER_ID).orElseThrow();
        assertTrue(verifiedUser.isEnabled());
        assertNull(verifiedUser.getVerificationToken());
    }

    @Test
    @Transactional
    void verifyEmail_WithInvalidToken_ThrowsException() {
        // Given: An invalid verification token
        String invalidToken = "invalid-token-that-doesnt-exist";

        // When/Then: Verifying should throw an exception
        assertThrows(ResourceNotFoundException.class, () -> 
            verificationService.verifyEmail(invalidToken));
    }

    @Test
    @Transactional
    void verifyEmailAndGetResponse_WithValidToken_ReturnsSuccessResponse() {
        // Given: A known unverified user with verification token
        User unverifiedUser = userRepository.findById(TestDataInitializer.UNVERIFIED_USER_ID).orElseThrow();
        String token = unverifiedUser.getVerificationToken();

        // When: We verify the email and get response
        VerificationResponse response = verificationService.verifyEmailAndGetResponse(token);

        // Then: Response should indicate success
        assertNotNull(response);
        assertTrue(response.isSuccess());
        assertTrue(response.getMessage().contains("verified successfully"));
        
        // Verify user is now verified in database
        User verifiedUser = userRepository.findById(TestDataInitializer.UNVERIFIED_USER_ID).orElseThrow();
        assertTrue(verifiedUser.isEnabled());
    }

    @Test
    @Transactional
    void resendVerificationEmail_ForUnverifiedUser_ReturnsSuccessResponse() {
        // Given: A known unverified user
        String email = "unverified@example.com";

        // When: We resend verification email
        GenericResponse response = verificationService.resendVerificationEmail(email);

        // Then: Response should indicate success
        assertNotNull(response);
        assertTrue(response.isSuccess());
        assertTrue(response.getMessage().contains("resent"));
    }

    @Test
    @Transactional
    void resendVerificationEmail_ForVerifiedUser_ReturnsFalseResponse() {
        // Given: A known verified user
        String email = "user@example.com";

        // When: We resend verification email
        GenericResponse response = verificationService.resendVerificationEmail(email);

        // Then: Response should indicate failure (can't resend to verified user)
        assertNotNull(response);
        assertFalse(response.isSuccess());
        assertTrue(response.getMessage().contains("Failed"));
    }
} 