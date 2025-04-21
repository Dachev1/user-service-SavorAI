package dev.idachev.userservice.web;

import dev.idachev.userservice.exception.ResourceNotFoundException;
import dev.idachev.userservice.exception.VerificationException;
import dev.idachev.userservice.security.JwtAuthenticationFilter;
import dev.idachev.userservice.service.VerificationService;
import dev.idachev.userservice.web.dto.AuthResponse;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.FilterType;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.BDDMockito.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(value = VerificationController.class,
        excludeAutoConfiguration = SecurityAutoConfiguration.class,
        excludeFilters = @ComponentScan.Filter(type = FilterType.ASSIGNABLE_TYPE, classes = JwtAuthenticationFilter.class)
)
@DisplayName("VerificationController Tests")
class VerificationControllerApiTest {

    @Autowired
    private MockMvc mockMvc;
    @MockitoBean
    private VerificationService verificationService;

    @Test
    @DisplayName("GET /status - Success")
    void getVerificationStatus_Success() throws Exception {
        String email = "verified@example.com";
        AuthResponse mockAuthResponse = AuthResponse.builder()
                .username("verifiedUser").email(email).enabled(true)
                .verificationPending(false).token("some-jwt-token")
                .success(true).message("User is verified").build();

        given(verificationService.getVerificationStatus(email)).willReturn(mockAuthResponse);

        mockMvc.perform(get("/api/v1/verification/status")
                        .param("email", email))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.enabled").value(true))
                .andExpect(jsonPath("$.verificationPending").value(false))
                .andExpect(jsonPath("$.email").value(email))
                .andExpect(jsonPath("$.token").exists());

        then(verificationService).should().getVerificationStatus(email);
    }

    @Test
    @DisplayName("POST /resend - Success")
    void resendVerificationEmail_Success() throws Exception {
        String email = "unverified@example.com";

        mockMvc.perform(post("/api/v1/verification/resend")
                        .with(csrf())
                        .param("email", email))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.message").value("Verification email resent. Please check your inbox."));

        then(verificationService).should().resendVerificationEmail(email);
    }

    @Test
    @DisplayName("GET /verify/{token} - Success Redirect")
    void verifyEmailRedirect_Success() throws Exception {
        String token = "valid-verification-token";
        String expectedRedirectUrl = "http://localhost:5173/signin?verified=true";

        mockMvc.perform(get("/api/v1/verification/verify/{token}", token))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl(expectedRedirectUrl));

        then(verificationService).should().verifyEmail(token);
    }

    @Test
    @DisplayName("POST /verify (API) - Success")
    void verifyEmailApi_Success() throws Exception {
        String token = "valid-api-verification-token";

        mockMvc.perform(post("/api/v1/verification/verify")
                        .with(csrf())
                        .param("token", token))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.message").value("Your email has been verified successfully."));

        then(verificationService).should().verifyEmail(token);
    }

    @Test
    @DisplayName("GET /status - Failure (Not Found)")
    void getVerificationStatus_Failure_NotFound() throws Exception {
        String email = "notfound@example.com";

        given(verificationService.getVerificationStatus(email))
                .willThrow(new ResourceNotFoundException("User not found"));

        mockMvc.perform(get("/api/v1/verification/status")
                        .param("email", email))
                .andExpect(status().isNotFound());
    }

    @Test
    @DisplayName("POST /resend - Failure (Not Found)")
    void resendVerificationEmail_Failure_NotFound() throws Exception {
        String email = "notfound@example.com";

        willThrow(new ResourceNotFoundException("User not found"))
                .given(verificationService).resendVerificationEmail(email);

        mockMvc.perform(post("/api/v1/verification/resend")
                        .with(csrf())
                        .param("email", email))
                .andExpect(status().isNotFound());
    }

    @Test
    @DisplayName("POST /resend - Failure (Already Verified)")
    void resendVerificationEmail_Failure_AlreadyVerified() throws Exception {
        String email = "alreadyverified@example.com";

        willThrow(new VerificationException("Account is already verified"))
                .given(verificationService).resendVerificationEmail(email);

        mockMvc.perform(post("/api/v1/verification/resend")
                        .with(csrf())
                        .param("email", email))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("GET /verify/{token} - Failure Redirect (Invalid Token)")
    void verifyEmailRedirect_Failure_InvalidToken() throws Exception {
        String token = "invalid-token";
        String errorMessage = "Invalid or expired token";
        String expectedRedirectUrl = "http://localhost:5173/signin?verified=false&error=Invalid+or+expired+token";

        willThrow(new VerificationException(errorMessage))
                .given(verificationService).verifyEmail(token);

        mockMvc.perform(get("/api/v1/verification/verify/{token}", token))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl(expectedRedirectUrl));
    }

    @Test
    @DisplayName("POST /verify (API) - Failure (Invalid Token)")
    void verifyEmailApi_Failure_InvalidToken() throws Exception {
        String token = "invalid-api-token";
        String errorMessage = "Invalid or expired token";

        willThrow(new VerificationException(errorMessage))
                .given(verificationService).verifyEmail(token);

        mockMvc.perform(post("/api/v1/verification/verify")
                        .with(csrf())
                        .param("token", token))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.message").value(errorMessage));
    }
} 