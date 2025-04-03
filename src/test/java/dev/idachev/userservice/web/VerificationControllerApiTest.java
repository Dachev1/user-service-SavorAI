package dev.idachev.userservice.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.idachev.userservice.config.JwtConfig;
import dev.idachev.userservice.config.SecurityConfig;
import dev.idachev.userservice.service.TokenBlacklistService;
import dev.idachev.userservice.service.UserDetailsService;
import dev.idachev.userservice.service.VerificationService;
import dev.idachev.userservice.web.dto.*;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(VerificationController.class)
@Import(SecurityConfig.class)
public class VerificationControllerApiTest {

    @MockitoBean
    private VerificationService verificationService;

    @MockitoBean
    private JwtConfig jwtConfig;

    @MockitoBean
    private TokenBlacklistService tokenBlacklistService;

    @MockitoBean
    private AuthenticationManager authenticationManager;

    @MockitoBean
    private UserDetailsService userDetailsService;

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    void getVerificationStatus_ReturnsStatus() throws Exception {

        // Given
        String email = "user@example.com";
        AuthResponse response = AuthResponse.builder()
                .verified(false)
                .build();

        when(verificationService.getVerificationStatus(email)).thenReturn(response);

        // When
        MockHttpServletRequestBuilder request = get("/api/v1/verification/status")
                .param("email", email);

        // Then
        mockMvc.perform(request)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.verified").value(false));
    }

    @Test
    void resendVerificationEmail_ReturnsSuccess() throws Exception {

        // Given
        EmailVerificationRequest request = new EmailVerificationRequest("user@example.com");
        EmailVerificationResponse response = EmailVerificationResponse.builder()
                .success(true)
                .message("Verification email sent")
                .build();

        when(verificationService.resendVerificationEmailWithResponse(any())).thenReturn(response);

        // When
        MockHttpServletRequestBuilder requestBuilder = post("/api/v1/verification/resend")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request));

        // Then
        mockMvc.perform(requestBuilder)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.message").value("Verification email sent"));
    }

    @Test
    void verifyEmail_RedirectsToLogin() throws Exception {

        // Given
        String token = "verification-token";
        VerificationResult result = VerificationResult.builder()
                .success(true)
                .build();

        when(verificationService.verifyEmailForRedirect(token)).thenReturn(result);

        // When
        MockHttpServletRequestBuilder request = get("/api/v1/verification/verify/{token}", token);

        // Then
        mockMvc.perform(request)
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrlPattern("**/signin?verified=true"));
    }

    @Test
    void verifyEmailApi_ReturnsSuccess() throws Exception {

        // Given
        TokenRequest request = new TokenRequest("verification-token");
        VerificationResponse response = VerificationResponse.builder()
                .success(true)
                .message("Email verified successfully")
                .build();

        when(verificationService.verifyEmailAndGetResponse(any())).thenReturn(response);

        // When
        MockHttpServletRequestBuilder requestBuilder = post("/api/v1/verification/verify")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request));

        // Then
        mockMvc.perform(requestBuilder)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.message").value("Email verified successfully"));
    }
} 