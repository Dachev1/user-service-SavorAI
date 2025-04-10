package dev.idachev.userservice.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.idachev.userservice.config.ApiTestConfig;
import dev.idachev.userservice.exception.ResourceNotFoundException;
import dev.idachev.userservice.service.VerificationService;
import dev.idachev.userservice.web.dto.AuthResponse;
import dev.idachev.userservice.web.dto.GenericResponse;
import dev.idachev.userservice.web.dto.VerificationResponse;
import dev.idachev.userservice.web.dto.VerificationResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

import java.time.LocalDateTime;

import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(VerificationController.class)
@Import(ApiTestConfig.class)
public class VerificationControllerApiTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockitoBean
    private VerificationService verificationService;

    private AuthResponse verifiedAuthResponse;
    private AuthResponse unverifiedAuthResponse;
    private GenericResponse successResponse;
    private GenericResponse failureResponse;
    private VerificationResponse verificationSuccessResponse;
    private VerificationResult verificationResult;
    private String testEmail;
    private String testToken;

    @BeforeEach
    void setUp() {
        testEmail = "test@example.com";
        testToken = "test-verification-token";

        // Set up verified auth response
        verifiedAuthResponse = AuthResponse.builder()
                .username("testuser")
                .email(testEmail)
                .token("jwt-token")
                .verified(true)
                .success(true)
                .message("")
                .build();

        // Set up unverified auth response
        unverifiedAuthResponse = AuthResponse.builder()
                .username("testuser")
                .email(testEmail)
                .token("")
                .verified(false)
                .success(true)
                .message("")
                .build();

        // Set up success response
        successResponse = GenericResponse.builder()
                .status(200)
                .message("Verification email has been resent. Please check your inbox.")
                .timestamp(LocalDateTime.now())
                .success(true)
                .build();

        // Set up failure response
        failureResponse = GenericResponse.builder()
                .status(400)
                .message("Failed to resend verification email. Please try again later.")
                .timestamp(LocalDateTime.now())
                .success(false)
                .build();

        // Set up verification success response
        verificationSuccessResponse = VerificationResponse.builder()
                .success(true)
                .message("Your email has been verified successfully. You can now sign in to your account.")
                .timestamp(LocalDateTime.now())
                .data(null)
                .build();

        // Set up verification result
        verificationResult = VerificationResult.success();
    }

    @Test
    public void getVerificationStatus_WhenUserExists_ReturnsStatus() throws Exception {
        // Given
        when(verificationService.getVerificationStatus(eq(testEmail))).thenReturn(verifiedAuthResponse);

        // When
        ResultActions result = mockMvc.perform(get("/api/v1/verification/status")
                .param("email", testEmail)
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON));

        // Then
        result.andExpect(status().isOk())
                .andExpect(jsonPath("$.email", is(testEmail)))
                .andExpect(jsonPath("$.verified", is(true)))
                .andExpect(jsonPath("$.token", is("jwt-token")));

        verify(verificationService, times(1)).getVerificationStatus(eq(testEmail));
    }

    @Test
    public void getVerificationStatus_WhenUserDoesNotExist_ReturnsNotFound() throws Exception {
        // Given
        String nonExistentEmail = "nonexistent@example.com";
        when(verificationService.getVerificationStatus(eq(nonExistentEmail)))
                .thenThrow(new ResourceNotFoundException("User not found with email: " + nonExistentEmail));

        // When
        ResultActions result = mockMvc.perform(get("/api/v1/verification/status")
                .param("email", nonExistentEmail)
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON));

        // Then
        result.andExpect(status().isNotFound());

        verify(verificationService, times(1)).getVerificationStatus(eq(nonExistentEmail));
    }

    @Test
    public void getVerificationStatus_WhenInvalidEmail_ReturnsBadRequest() throws Exception {
        // Given
        String invalidEmail = "invalid-email";

        // When
        ResultActions result = mockMvc.perform(get("/api/v1/verification/status")
                .param("email", invalidEmail)
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON));

        // Then
        result.andExpect(status().isBadRequest());

        verify(verificationService, never()).getVerificationStatus(anyString());
    }

    @Test
    public void resendVerificationEmail_WhenUserExists_ReturnsSuccess() throws Exception {
        // Given
        when(verificationService.resendVerificationEmail(eq(testEmail))).thenReturn(successResponse);

        // When
        ResultActions result = mockMvc.perform(post("/api/v1/verification/resend")
                .param("email", testEmail)
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON));

        // Then
        result.andExpect(status().isOk())
                .andExpect(jsonPath("$.success", is(true)))
                .andExpect(jsonPath("$.message", is("Verification email has been resent. Please check your inbox.")));

        verify(verificationService, times(1)).resendVerificationEmail(eq(testEmail));
    }

    @Test
    public void resendVerificationEmail_WhenUserAlreadyVerified_ReturnsFailure() throws Exception {
        // Given
        when(verificationService.resendVerificationEmail(eq(testEmail))).thenReturn(failureResponse);

        // When
        ResultActions result = mockMvc.perform(post("/api/v1/verification/resend")
                .param("email", testEmail)
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON));

        // Then
        result.andExpect(status().isOk())
                .andExpect(jsonPath("$.success", is(false)))
                .andExpect(jsonPath("$.message", is("Failed to resend verification email. Please try again later.")));

        verify(verificationService, times(1)).resendVerificationEmail(eq(testEmail));
    }

    @Test
    public void resendVerificationEmail_WhenUserDoesNotExist_ReturnsNotFound() throws Exception {
        // Given
        String nonExistentEmail = "nonexistent@example.com";
        when(verificationService.resendVerificationEmail(eq(nonExistentEmail)))
                .thenThrow(new ResourceNotFoundException("User not found with email: " + nonExistentEmail));

        // When
        ResultActions result = mockMvc.perform(post("/api/v1/verification/resend")
                .param("email", nonExistentEmail)
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON));

        // Then
        result.andExpect(status().isNotFound());

        verify(verificationService, times(1)).resendVerificationEmail(eq(nonExistentEmail));
    }

    @Test
    public void verifyEmail_WhenValidToken_RedirectsToSignin() throws Exception {
        // Given
        when(verificationService.verifyEmailForRedirect(eq(testToken))).thenReturn(verificationResult);

        // When
        ResultActions result = mockMvc.perform(get("/api/v1/verification/verify/{token}", testToken)
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON));

        // Then
        result.andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("http://localhost:5173/signin?verified=true"));

        verify(verificationService, times(1)).verifyEmailForRedirect(eq(testToken));
    }

    @Test
    public void verifyEmail_WhenInvalidToken_RedirectsToSigninWithError() throws Exception {
        // Given
        String invalidToken = "invalid-token";
        VerificationResult failureResult = VerificationResult.failure("ResourceNotFoundException");

        when(verificationService.verifyEmailForRedirect(eq(invalidToken))).thenReturn(failureResult);

        // When
        ResultActions result = mockMvc.perform(get("/api/v1/verification/verify/{token}", invalidToken)
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON));

        // Then
        result.andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("http://localhost:5173/signin?verified=false&error=ResourceNotFoundException"));

        verify(verificationService, times(1)).verifyEmailForRedirect(eq(invalidToken));
    }

    @Test
    public void verifyEmailApi_WhenValidToken_ReturnsSuccess() throws Exception {
        // Given
        when(verificationService.verifyEmailAndGetResponse(eq(testToken))).thenReturn(verificationSuccessResponse);

        // When
        ResultActions result = mockMvc.perform(post("/api/v1/verification/verify")
                .param("token", testToken)
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON));

        // Then
        result.andExpect(status().isOk())
                .andExpect(jsonPath("$.success", is(true)))
                .andExpect(jsonPath("$.message", is("Your email has been verified successfully. You can now sign in to your account.")));

        verify(verificationService, times(1)).verifyEmailAndGetResponse(eq(testToken));
    }

    @Test
    public void verifyEmailApi_WhenInvalidToken_ReturnsNotFound() throws Exception {
        // Given
        String invalidToken = "invalid-token";
        when(verificationService.verifyEmailAndGetResponse(eq(invalidToken)))
                .thenThrow(new ResourceNotFoundException("Invalid verification token"));

        // When
        ResultActions result = mockMvc.perform(post("/api/v1/verification/verify")
                .param("token", invalidToken)
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON));

        // Then
        result.andExpect(status().isNotFound());

        verify(verificationService, times(1)).verifyEmailAndGetResponse(eq(invalidToken));
    }
} 