package dev.idachev.userservice.integration;

import dev.idachev.userservice.model.Role;
import dev.idachev.userservice.model.User;
import dev.idachev.userservice.repository.UserRepository;
import dev.idachev.userservice.service.TokenBlacklistService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

// TODO: Remember to use @MockitoBean for TokenBlacklistService in integration tests
// TODO: Consider adding tests for email content if email sending is mocked/captured (requires mocking JavaMailSender).
// Note: Rate limiting tests for /resend endpoint would require specialized setup and are omitted here. Manual testing suggested if feature exists.
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Transactional
class VerificationITest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository userRepository;

    @MockitoBean
    private TokenBlacklistService tokenBlacklistService;

    // --- Helper Methods ---

    private User createUser(String username, String email, String password, Role role, boolean enabled, String verificationToken) {
        User user = User.builder()
                .username(username)
                .email(email)
                .password(password) // Raw password for test simplicity
                .role(role)
                .enabled(enabled)
                .verificationToken(verificationToken)
                .build();
        return userRepository.save(user);
    }

    private User createUnverifiedUser(String username, String email, String password, String token) {
        return createUser(username, email, password, Role.USER, false, token);
    }

    private User createVerifiedUser(String username, String email, String password) {
        return createUser(username, email, password, Role.USER, true, null);
    }

    // --- Verification Status Tests ---

    @Test
    void givenVerifiedUser_whenGetVerificationStatus_thenOkAndEnabledTrue() throws Exception {
        String email = "verified@example.com";
        createVerifiedUser("verified_user", email, "password123");

        mockMvc.perform(get("/api/v1/verification/status")
                        .param("email", email))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.enabled").value(true))
                .andExpect(jsonPath("$.verificationPending").value(false))
                .andExpect(jsonPath("$.token").isNotEmpty());
    }

    @Test
    void givenUnverifiedUser_whenGetVerificationStatus_thenOkAndEnabledFalse() throws Exception {
        String email = "unverified@example.com";
        createUnverifiedUser("unverified_user", email, "password123", "some-token");

        mockMvc.perform(get("/api/v1/verification/status")
                        .param("email", email))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.enabled").value(false))
                .andExpect(jsonPath("$.verificationPending").value(true))
                .andExpect(jsonPath("$.token").isEmpty());
    }

    @Test
    void givenNonExistentEmail_whenGetVerificationStatus_thenNotFound() throws Exception {
        String email = "nonexistent@example.com";
        mockMvc.perform(get("/api/v1/verification/status")
                        .param("email", email))
                .andExpect(status().isNotFound());
    }

    @Test
    void givenInvalidEmailFormat_whenGetVerificationStatus_thenBadRequest() throws Exception {
        String invalidEmail = "invalid-email-format";
        mockMvc.perform(get("/api/v1/verification/status")
                        .param("email", invalidEmail))
                .andExpect(status().isBadRequest());
    }

    // --- Resend Verification Tests ---

    @Test
    void givenUnverifiedUser_whenResendVerification_thenOk() throws Exception {
        String email = "resend_unverified@example.com";
        String initialToken = "initial-token-for-resend";
        createUnverifiedUser("resend_user", email, "password123", initialToken);

        mockMvc.perform(post("/api/v1/verification/resend")
                        .param("email", email))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.message").value("Verification email resent. Please check your inbox."));

        User userAfterResend = userRepository.findByEmail(email).orElseThrow();
        assertThat(userAfterResend.isEnabled()).isFalse();
        assertThat(userAfterResend.getVerificationToken()).isNotNull(); // Token should be regenerated/resent
    }

    @Test
    void givenVerifiedUser_whenResendVerification_thenBadRequest() throws Exception {
        String email = "resend_verified@example.com";
        createVerifiedUser("resend_verified_user", email, "password123");

        mockMvc.perform(post("/api/v1/verification/resend")
                        .param("email", email))
                .andExpect(status().isBadRequest());
    }

    @Test
    void givenNonExistentEmail_whenResendVerification_thenNotFound() throws Exception {
        String email = "resend_nonexistent@example.com";
        mockMvc.perform(post("/api/v1/verification/resend")
                        .param("email", email))
                .andExpect(status().isNotFound());
    }

    @Test
    void givenInvalidEmailFormat_whenResendVerification_thenBadRequest() throws Exception {
        String invalidEmail = "resend-invalid-format";
        mockMvc.perform(post("/api/v1/verification/resend")
                        .param("email", invalidEmail))
                .andExpect(status().isBadRequest());
    }

    // --- Verify Email (API) Tests ---

    @Test
    void givenValidToken_whenVerifyEmailApi_thenOkAndUserEnabled() throws Exception {
        String email = "verifyapi@example.com";
        String validToken = "valid-api-token-123";
        createUnverifiedUser("verifyapi_user", email, "password123", validToken);

        mockMvc.perform(post("/api/v1/verification/verify")
                        .param("token", validToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.message").value("Your email has been verified successfully."));

        User verifiedUser = userRepository.findByEmail(email).orElseThrow();
        assertThat(verifiedUser.isEnabled()).isTrue();
        assertThat(verifiedUser.getVerificationToken()).isNull(); // Token should be cleared after verification
    }

    @Test
    void givenInvalidToken_whenVerifyEmailApi_thenBadRequest() throws Exception {
        String invalidToken = "invalid-or-nonexistent-token";
        mockMvc.perform(post("/api/v1/verification/verify")
                        .param("token", invalidToken))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.message").isNotEmpty()); // Expect failure message
    }

    @Test
    void givenExpiredToken_whenVerifyEmailApi_thenBadRequest() throws Exception {
        // Assuming expired tokens are handled similarly to invalid ones
        String expiredToken = "theoretically-expired-token";
        mockMvc.perform(post("/api/v1/verification/verify")
                        .param("token", expiredToken))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.message").isNotEmpty()); // Expect failure message
    }

    @Test
    void givenTokenForAlreadyVerifiedUser_whenVerifyEmailApi_thenBadRequest() throws Exception {
        String email = "verifyapi_already@example.com";
        String tokenToUse = "token-for-already-verified";
        // 1. Create unverified user
        User user = createUnverifiedUser("verifyapi_already_user", email, "password123", tokenToUse);
        assertThat(user.isEnabled()).isFalse();
        assertThat(user.getVerificationToken()).isEqualTo(tokenToUse);

        // 2. Verify the user successfully (this should enable user and nullify the token)
        mockMvc.perform(post("/api/v1/verification/verify")
                        .param("token", tokenToUse))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));

        // Fetch user again to confirm state
        User userAfterVerification = userRepository.findByEmail(email).orElseThrow();
        assertThat(userAfterVerification.isEnabled()).isTrue();
        assertThat(userAfterVerification.getVerificationToken()).isNull(); // Token should be gone

        // 3. Attempt to verify AGAIN using the SAME token
        mockMvc.perform(post("/api/v1/verification/verify")
                        .param("token", tokenToUse)) // Using the now invalid/used token
                .andExpect(status().isBadRequest()) // Expect failure
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.message").isNotEmpty()); // Expect failure message
    }

    // --- Verify Email (Redirect) Tests ---

    @Test
    void givenValidToken_whenVerifyEmailRedirect_thenRedirectSuccess() throws Exception {
        String email = "verifyredirect@example.com";
        String validToken = "valid-redirect-token-456";
        createUnverifiedUser("verifyredirect_user", email, "password123", validToken);

        mockMvc.perform(get("/api/v1/verification/verify/{token}", validToken))
                .andExpect(status().isFound()) // Expect 302
                .andExpect(redirectedUrl("http://localhost:5173/signin?verified=true")); // Success redirect

        User verifiedUser = userRepository.findByEmail(email).orElseThrow();
        assertThat(verifiedUser.isEnabled()).isTrue();
        assertThat(verifiedUser.getVerificationToken()).isNull(); // Token should be cleared
    }

    @Test
    void givenInvalidToken_whenVerifyEmailRedirect_thenRedirectError() throws Exception {
        String invalidToken = "invalid-redirect-token";
        mockMvc.perform(get("/api/v1/verification/verify/{token}", invalidToken))
                .andExpect(status().isFound()) // Expect 302
                .andExpect(redirectedUrl("http://localhost:5173/signin?verified=false&error=Invalid+or+expired+verification+token.")); // Expect redirect to signin with specific error
    }

    @Test
    void givenExpiredToken_whenVerifyEmailRedirect_thenRedirectError() throws Exception {
        // Assuming expired tokens are handled similarly to invalid ones
        String expiredToken = "theoretically-expired-redirect-token";
        mockMvc.perform(get("/api/v1/verification/verify/{token}", expiredToken))
                .andExpect(status().isFound()) // Expect 302
                .andExpect(redirectedUrl("http://localhost:5173/signin?verified=false&error=Invalid+or+expired+verification+token.")); // Error redirect
    }

    @Test
    void givenTokenForAlreadyVerifiedUser_whenVerifyEmailRedirect_thenRedirectError() throws Exception {
        String email = "verifyredirect_already@example.com";
        String tokenToUse = "token-for-redirect-already-verified";
        // 1. Create unverified user
        User user = createUnverifiedUser("verifyredirect_already_user", email, "password123", tokenToUse);
        assertThat(user.isEnabled()).isFalse();
        assertThat(user.getVerificationToken()).isEqualTo(tokenToUse);

        // 2. Verify the user successfully via redirect (this should enable user and nullify the token)
        mockMvc.perform(get("/api/v1/verification/verify/{token}", tokenToUse))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("http://localhost:5173/signin?verified=true")); // Successful verification

        // Fetch user again to confirm state
        User userAfterVerification = userRepository.findByEmail(email).orElseThrow();
        assertThat(userAfterVerification.isEnabled()).isTrue();
        assertThat(userAfterVerification.getVerificationToken()).isNull(); // Token should be gone

        // 3. Attempt to verify AGAIN using the SAME token via redirect
        mockMvc.perform(get("/api/v1/verification/verify/{token}", tokenToUse)) // Using the now invalid/used token
                .andExpect(status().isFound()) // Still expect 302 redirect
                .andExpect(redirectedUrl("http://localhost:5173/signin?verified=false&error=Invalid+or+expired+verification+token.")); // Expect redirect to signin with error
    }

}
