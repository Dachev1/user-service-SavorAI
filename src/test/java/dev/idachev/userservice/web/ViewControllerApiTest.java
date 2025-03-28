package dev.idachev.userservice.web;

import dev.idachev.userservice.config.JwtConfig;
import dev.idachev.userservice.config.SecurityConfig;
import dev.idachev.userservice.service.TokenBlacklistService;
import dev.idachev.userservice.service.UserService;
import dev.idachev.userservice.web.dto.VerificationResponse;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrlPattern;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(ViewController.class)
@Import(SecurityConfig.class)
public class ViewControllerApiTest {

    @MockitoBean
    private UserService userService;

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

    @Test
    void verifyEmail_WithValidToken_RedirectsToLoginWithSuccess() throws Exception {

        // Given
        String token = "valid-token";
        VerificationResponse response = VerificationResponse.builder()
                .success(true)
                .message("Email successfully verified")
                .build();

        when(userService.verifyEmailAndGetResponse(token)).thenReturn(response);

        // When
        MockHttpServletRequestBuilder request = get("/api/v1/user/verify-email/{token}", token);

        // Then
        mockMvc.perform(request)
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrlPattern("http://localhost:5173/login?verified=true&message=*"));
    }

    @Test
    void verifyEmail_WithInvalidToken_RedirectsToLoginWithError() throws Exception {

        // Given
        String token = "invalid-token";
        VerificationResponse response = VerificationResponse.builder()
                .success(false)
                .message("Invalid verification token")
                .build();

        when(userService.verifyEmailAndGetResponse(token)).thenReturn(response);

        // When
        MockHttpServletRequestBuilder request = get("/api/v1/user/verify-email/{token}", token);

        // Then
        mockMvc.perform(request)
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrlPattern("http://localhost:5173/login?verified=false&message=*"));
    }

    @Test
    void verifyEmail_WithEmptyToken_RedirectsToLoginWithError() throws Exception {

        // When
        // Use a direct path instead of an empty path variable
        MockHttpServletRequestBuilder request = get("/api/v1/user/verify-email/");

        // Then
        mockMvc.perform(request)
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrlPattern("http://localhost:5173/login?verified=false&message=*"));
    }
}