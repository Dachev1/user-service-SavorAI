package dev.idachev.userservice.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.idachev.userservice.config.JwtConfig;
import dev.idachev.userservice.config.SecurityConfig;
import dev.idachev.userservice.service.AuthenticationService;
import dev.idachev.userservice.service.TokenBlacklistService;
import dev.idachev.userservice.service.UserService;
import dev.idachev.userservice.web.dto.*;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(UserController.class)
@Import(SecurityConfig.class)
public class UserControllerApiTest {

    @MockitoBean
    private UserService userService;

    @MockitoBean
    private AuthenticationService authenticationService;

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
    void register_ReturnsCreatedAndToken() throws Exception {

        // Given
        RegisterRequest request = RegisterRequest.builder()
                .username("testuser")
                .email("user@example.com")
                .password("password123")
                .build();

        AuthResponse response = AuthResponse.builder()
                .token("jwt-token")
                .verified(false)
                .build();

        when(userService.register(any())).thenReturn(response);

        // When
        MockHttpServletRequestBuilder requestBuilder = post("/api/v1/user/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request));

        // Then
        mockMvc.perform(requestBuilder)
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.token").value("jwt-token"))
                .andExpect(jsonPath("$.verified").value(false));
    }

    @Test
    void login_ReturnsTokenAndUserInfo() throws Exception {

        // Given
        LoginRequest request = LoginRequest.builder()
                .email("user@example.com")
                .password("password123")
                .build();

        AuthResponse response = AuthResponse.builder()
                .token("jwt-token")
                .verified(true)
                .build();

        when(authenticationService.login(any())).thenReturn(response);

        // When
        MockHttpServletRequestBuilder requestBuilder = post("/api/v1/user/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request));

        // Then
        mockMvc.perform(requestBuilder)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").value("jwt-token"))
                .andExpect(jsonPath("$.verified").value(true));
    }

    @Test
    @WithMockUser
    void getCurrentUser_ReturnsUserInfo() throws Exception {

        // Given
        UserResponse userResponse = UserResponse.builder()
                .id(UUID.randomUUID())
                .email("user@example.com")
                .role("USER")
                .build();

        when(authenticationService.getCurrentUserInfo()).thenReturn(userResponse);

        // When
        MockHttpServletRequestBuilder request = get("/api/v1/user/current-user");

        // Then
        mockMvc.perform(request)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").exists())
                .andExpect(jsonPath("$.email").value("user@example.com"))
                .andExpect(jsonPath("$.role").value("USER"));
    }

    @Test
    @WithMockUser
    void logout_ReturnsSuccess() throws Exception {

        // Given
        GenericResponse response = GenericResponse.builder()
                .message("Logged out successfully")
                .build();

        when(authenticationService.logout(any())).thenReturn(response);

        // When
        MockHttpServletRequestBuilder request = post("/api/v1/user/logout")
                .header("Authorization", "Bearer jwt-token");

        // Then
        mockMvc.perform(request)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Logged out successfully"));
    }
} 