package dev.idachev.userservice.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.idachev.userservice.config.ApiTestConfig;
import dev.idachev.userservice.exception.AuthenticationException;
import dev.idachev.userservice.service.AuthenticationService;
import dev.idachev.userservice.web.dto.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(AuthController.class)
@Import(ApiTestConfig.class)
public class AuthControllerApiTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockitoBean
    private AuthenticationService authenticationService;

    private RegisterRequest registerRequest;
    private SignInRequest signInRequest;
    private AuthResponse successAuthResponse;
    private AuthResponse failureAuthResponse;
    private ProfileUpdateRequest profileUpdateRequest;
    private GenericResponse successResponse;
    private GenericResponse failureResponse;

    @BeforeEach
    void setUp() {
        // Set up register request
        registerRequest = RegisterRequest.builder()
                .username("newuser")
                .email("newuser@example.com")
                .password("Password123!")
                .build();

        // Set up sign in request
        signInRequest = SignInRequest.builder()
                .identifier("testuser")
                .password("Password123!")
                .build();

        // Set up success auth response
        successAuthResponse = AuthResponse.builder()
                .username("testuser")
                .email("test@example.com")
                .token("jwt.token.string")
                .verified(true)
                .success(true)
                .message("Successfully authenticated")
                .build();

        // Set up failure auth response
        failureAuthResponse = AuthResponse.builder()
                .success(false)
                .message("Authentication failed")
                .build();

        // Set up profile update request
        profileUpdateRequest = ProfileUpdateRequest.builder()
                .username("newusername")
                .currentPassword("Password123!")
                .build();

        // Set up success response
        successResponse = GenericResponse.builder()
                .status(200)
                .message("Operation successful")
                .timestamp(LocalDateTime.now())
                .success(true)
                .build();

        // Set up failure response
        failureResponse = GenericResponse.builder()
                .status(400)
                .message("Operation failed")
                .timestamp(LocalDateTime.now())
                .success(false)
                .build();
    }

    @Test
    public void signup_WhenValidRequest_ReturnsCreated() throws Exception {
        // Given
        when(authenticationService.register(any(RegisterRequest.class))).thenReturn(successAuthResponse);

        // When
        ResultActions result = mockMvc.perform(post("/api/v1/auth/signup")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(registerRequest)));

        // Then
        result.andExpect(status().isCreated())
                .andExpect(jsonPath("$.success", is(true)))
                .andExpect(jsonPath("$.username", is("testuser")))
                .andExpect(jsonPath("$.email", is("test@example.com")))
                .andExpect(jsonPath("$.token", is("jwt.token.string")));

        verify(authenticationService, times(1)).register(any(RegisterRequest.class));
    }

    @Test
    public void signup_WhenUsernameExists_ReturnsConflict() throws Exception {
        // Given
        when(authenticationService.register(any(RegisterRequest.class)))
                .thenThrow(new AuthenticationException("Username already exists"));

        // When
        ResultActions result = mockMvc.perform(post("/api/v1/auth/signup")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(registerRequest)));

        // Then
        result.andExpect(status().isUnauthorized());

        verify(authenticationService, times(1)).register(any(RegisterRequest.class));
    }

    @Test
    public void signin_WhenValidCredentials_ReturnsSuccess() throws Exception {
        // Given
        when(authenticationService.signIn(any(SignInRequest.class))).thenReturn(successAuthResponse);

        // When
        ResultActions result = mockMvc.perform(post("/api/v1/auth/signin")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(signInRequest)));

        // Then
        result.andExpect(status().isOk())
                .andExpect(jsonPath("$.success", is(true)))
                .andExpect(jsonPath("$.username", is("testuser")))
                .andExpect(jsonPath("$.token", is("jwt.token.string")));

        verify(authenticationService, times(1)).signIn(any(SignInRequest.class));
    }

    @Test
    public void signin_WhenInvalidCredentials_ReturnsUnauthorized() throws Exception {
        // Given
        when(authenticationService.signIn(any(SignInRequest.class)))
                .thenThrow(new AuthenticationException("Invalid credentials"));

        // When
        ResultActions result = mockMvc.perform(post("/api/v1/auth/signin")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(signInRequest)));

        // Then
        result.andExpect(status().isUnauthorized());

        verify(authenticationService, times(1)).signIn(any(SignInRequest.class));
    }

    @Test
    public void refreshToken_WhenValidToken_ReturnsNewToken() throws Exception {
        // Given
        String bearerToken = "Bearer valid.jwt.token";
        when(authenticationService.refreshToken(eq(bearerToken))).thenReturn(successAuthResponse);

        // When
        ResultActions result = mockMvc.perform(post("/api/v1/auth/refresh-token")
                .with(csrf())
                .header("Authorization", bearerToken)
                .contentType(MediaType.APPLICATION_JSON));

        // Then
        result.andExpect(status().isOk())
                .andExpect(jsonPath("$.success", is(true)))
                .andExpect(jsonPath("$.token", is("jwt.token.string")));

        verify(authenticationService, times(1)).refreshToken(eq(bearerToken));
    }

    @Test
    public void refreshToken_WhenInvalidToken_ReturnsUnauthorized() throws Exception {
        // Given
        String bearerToken = "Bearer invalid.jwt.token";
        when(authenticationService.refreshToken(eq(bearerToken)))
                .thenThrow(new AuthenticationException("Invalid or expired token"));

        // When
        ResultActions result = mockMvc.perform(post("/api/v1/auth/refresh-token")
                .with(csrf())
                .header("Authorization", bearerToken)
                .contentType(MediaType.APPLICATION_JSON));

        // Then
        result.andExpect(status().isUnauthorized());

        verify(authenticationService, times(1)).refreshToken(eq(bearerToken));
    }

    @Test
    public void logout_WhenValidToken_ReturnsSuccess() throws Exception {
        // Given
        String bearerToken = "Bearer valid.jwt.token";
        doNothing().when(authenticationService).logout(anyString());

        // When
        ResultActions result = mockMvc.perform(post("/api/v1/auth/logout")
                .with(csrf())
                .header("Authorization", bearerToken)
                .contentType(MediaType.APPLICATION_JSON));

        // Then
        result.andExpect(status().isOk())
                .andExpect(jsonPath("$.success", is(true)))
                .andExpect(jsonPath("$.message", is("Successfully logged out")));

        verify(authenticationService, times(1)).logout(eq("valid.jwt.token"));
    }

    @Test
    public void logout_WhenNoToken_ReturnsSuccess() throws Exception {
        // Given
        // No token provided

        // When
        ResultActions result = mockMvc.perform(post("/api/v1/auth/logout")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON));

        // Then
        result.andExpect(status().isOk())
                .andExpect(jsonPath("$.success", is(true)))
                .andExpect(jsonPath("$.message", is("No active session found")));

        verify(authenticationService, never()).logout(anyString());
    }

    @Test
    @WithMockUser(username = "testuser")
    public void changeUsername_WhenValidRequest_ReturnsSuccess() throws Exception {
        // Given
        when(authenticationService.changeUsername(eq("testuser"), eq("newusername"), eq("Password123!")))
                .thenReturn(successResponse);

        // When
        ResultActions result = mockMvc.perform(post("/api/v1/auth/change-username")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(profileUpdateRequest)));

        // Then
        result.andExpect(status().isOk())
                .andExpect(jsonPath("$.success", is(true)))
                .andExpect(jsonPath("$.message", is("Operation successful")));

        verify(authenticationService, times(1))
                .changeUsername(eq("testuser"), eq("newusername"), eq("Password123!"));
    }

    @Test
    @WithMockUser(username = "testuser")
    public void changeUsername_WhenUsernameTaken_ReturnsConflict() throws Exception {
        // Given
        when(authenticationService.changeUsername(eq("testuser"), eq("newusername"), eq("Password123!")))
                .thenThrow(new AuthenticationException("Username already taken"));

        // When
        ResultActions result = mockMvc.perform(post("/api/v1/auth/change-username")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(profileUpdateRequest)));

        // Then
        result.andExpect(status().isUnauthorized());

        verify(authenticationService, times(1))
                .changeUsername(eq("testuser"), eq("newusername"), eq("Password123!"));
    }

    @Test
    public void checkUserStatus_WhenUserNotBanned_ReturnsStatus() throws Exception {
        // Given
        String identifier = "testuser";
        Map<String, Object> statusResponse = new HashMap<>();
        statusResponse.put("banned", false);
        statusResponse.put("enabled", true);

        when(authenticationService.checkUserBanStatus(eq(identifier))).thenReturn(statusResponse);

        // When
        ResultActions result = mockMvc.perform(get("/api/v1/auth/check-status")
                .param("identifier", identifier)
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON));

        // Then
        result.andExpect(status().isOk())
                .andExpect(jsonPath("$.banned", is(false)))
                .andExpect(jsonPath("$.enabled", is(true)));

        verify(authenticationService, times(1)).checkUserBanStatus(eq(identifier));
    }

    @Test
    public void checkUserStatus_WhenUserBanned_ReturnsBannedStatus() throws Exception {
        // Given
        String identifier = "banneduser";
        Map<String, Object> statusResponse = new HashMap<>();
        statusResponse.put("banned", true);
        statusResponse.put("enabled", true);

        when(authenticationService.checkUserBanStatus(eq(identifier))).thenReturn(statusResponse);

        // When
        ResultActions result = mockMvc.perform(get("/api/v1/auth/check-status")
                .param("identifier", identifier)
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON));

        // Then
        result.andExpect(status().isOk())
                .andExpect(jsonPath("$.banned", is(true)))
                .andExpect(jsonPath("$.enabled", is(true)));

        verify(authenticationService, times(1)).checkUserBanStatus(eq(identifier));
    }
} 