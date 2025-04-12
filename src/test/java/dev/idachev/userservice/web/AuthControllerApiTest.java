package dev.idachev.userservice.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.idachev.userservice.config.TestSecurityConfig;
import dev.idachev.userservice.exception.AuthenticationException;
import dev.idachev.userservice.service.AuthenticationService;
import dev.idachev.userservice.web.dto.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(controllers = AuthController.class)
@AutoConfigureMockMvc(addFilters = false)
@Import(TestSecurityConfig.class)
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
    private ProfileUpdateRequest profileUpdateRequest;
    private GenericResponse successResponse;

    @BeforeEach
    void setUp() {
        registerRequest = RegisterRequest.builder()
                .username("newuser")
                .email("newuser@example.com")
                .password("Password123!")
                .build();

        signInRequest = SignInRequest.builder()
                .identifier("testuser")
                .password("Password123!")
                .build();

        successAuthResponse = AuthResponse.builder()
                .username("testuser")
                .email("test@example.com")
                .token("jwt.token.string")
                .verified(true)
                .success(true)
                .message("Successfully authenticated")
                .build();

        profileUpdateRequest = ProfileUpdateRequest.builder()
                .username("newusername")
                .currentPassword("Password123!")
                .build();

        successResponse = GenericResponse.builder()
                .status(200)
                .message("Operation successful")
                .timestamp(LocalDateTime.now())
                .success(true)
                .build();
    }

    @Test
    public void signup_validRequest_returnsCreated() throws Exception {
        when(authenticationService.register(any(RegisterRequest.class))).thenReturn(successAuthResponse);

        mockMvc.perform(post("/api/v1/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(registerRequest)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.success", is(true)))
                .andExpect(jsonPath("$.username", is("testuser")))
                .andExpect(jsonPath("$.token", is("jwt.token.string")));

        verify(authenticationService).register(any(RegisterRequest.class));
    }

    @Test
    public void signup_usernameExists_returnsUnauthorized() throws Exception {
        when(authenticationService.register(any(RegisterRequest.class)))
                .thenThrow(new AuthenticationException("Username already exists"));

        mockMvc.perform(post("/api/v1/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(registerRequest)))
                .andExpect(status().isUnauthorized());

        verify(authenticationService).register(any(RegisterRequest.class));
    }

    @Test
    public void signin_validCredentials_returnsSuccess() throws Exception {
        when(authenticationService.signIn(any(SignInRequest.class))).thenReturn(successAuthResponse);

        mockMvc.perform(post("/api/v1/auth/signin")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(signInRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success", is(true)))
                .andExpect(jsonPath("$.username", is("testuser")))
                .andExpect(jsonPath("$.token", is("jwt.token.string")));

        verify(authenticationService).signIn(any(SignInRequest.class));
    }

    @Test
    public void signin_invalidCredentials_returnsUnauthorized() throws Exception {
        when(authenticationService.signIn(any(SignInRequest.class)))
                .thenThrow(new AuthenticationException("Invalid credentials"));

        mockMvc.perform(post("/api/v1/auth/signin")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(signInRequest)))
                .andExpect(status().isUnauthorized());

        verify(authenticationService).signIn(any(SignInRequest.class));
    }

    @Test
    public void refreshToken_validToken_returnsNewToken() throws Exception {
        String bearerToken = "Bearer valid.jwt.token";
        when(authenticationService.refreshToken(eq(bearerToken))).thenReturn(successAuthResponse);

        mockMvc.perform(post("/api/v1/auth/refresh-token")
                        .header("Authorization", bearerToken)
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success", is(true)))
                .andExpect(jsonPath("$.token", is("jwt.token.string")));

        verify(authenticationService).refreshToken(eq(bearerToken));
    }

    @Test
    public void refreshToken_invalidToken_returnsUnauthorized() throws Exception {
        String bearerToken = "Bearer invalid.jwt.token";
        when(authenticationService.refreshToken(eq(bearerToken)))
                .thenThrow(new AuthenticationException("Invalid or expired token"));

        mockMvc.perform(post("/api/v1/auth/refresh-token")
                        .header("Authorization", bearerToken)
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isUnauthorized());

        verify(authenticationService).refreshToken(eq(bearerToken));
    }

    @Test
    public void logout_validToken_returnsSuccess() throws Exception {
        String bearerToken = "Bearer valid.jwt.token";
        doNothing().when(authenticationService).logout("valid.jwt.token");

        mockMvc.perform(post("/api/v1/auth/logout")
                        .header("Authorization", bearerToken)
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success", is(true)))
                .andExpect(jsonPath("$.message", is("Successfully logged out")));

        verify(authenticationService).logout("valid.jwt.token");
    }

    @Test
    public void logout_noToken_returnsSuccess() throws Exception {
        mockMvc.perform(post("/api/v1/auth/logout")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success", is(true)));

        verify(authenticationService, never()).logout(anyString());
    }

    @Test
    @WithMockUser(username = "testuser")
    public void changeUsername_validRequest_returnsSuccess() throws Exception {
        when(authenticationService.changeUsername(eq("testuser"), eq("newusername"), eq("Password123!")))
                .thenReturn(successResponse);

        mockMvc.perform(post("/api/v1/auth/change-username")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(profileUpdateRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success", is(true)));

        verify(authenticationService).changeUsername(eq("testuser"), eq("newusername"), eq("Password123!"));
    }

    @Test
    @WithMockUser(username = "testuser")
    public void changeUsername_usernameTaken_returnsUnauthorized() throws Exception {
        when(authenticationService.changeUsername(eq("testuser"), eq("newusername"), eq("Password123!")))
                .thenThrow(new AuthenticationException("Username already taken"));

        mockMvc.perform(post("/api/v1/auth/change-username")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(profileUpdateRequest)))
                .andExpect(status().isUnauthorized());

        verify(authenticationService).changeUsername(eq("testuser"), eq("newusername"), eq("Password123!"));
    }

    @Test
    public void checkUserStatus_userNotBanned_returnsStatus() throws Exception {
        Map<String, Object> statusResponse = new HashMap<>();
        statusResponse.put("success", true);
        statusResponse.put("banned", false);
        statusResponse.put("enabled", true);
        statusResponse.put("message", "Operation successful");

        when(authenticationService.checkUserBanStatus(anyString())).thenReturn(statusResponse);

        mockMvc.perform(get("/api/v1/auth/status")
                        .param("username", "testuser")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success", is(true)))
                .andExpect(jsonPath("$.banned", is(false)))
                .andExpect(jsonPath("$.enabled", is(true)));

        verify(authenticationService).checkUserBanStatus(eq("testuser"));
    }

    @Test
    public void checkUserStatus_userBanned_returnsBannedStatus() throws Exception {
        Map<String, Object> bannedResponse = new HashMap<>();
        bannedResponse.put("success", false);
        bannedResponse.put("banned", true);
        bannedResponse.put("enabled", true);
        bannedResponse.put("message", "User is banned");

        when(authenticationService.checkUserBanStatus(anyString())).thenReturn(bannedResponse);

        mockMvc.perform(get("/api/v1/auth/status")
                        .param("username", "banneduser")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success", is(false)))
                .andExpect(jsonPath("$.banned", is(true)))
                .andExpect(jsonPath("$.message", is("User is banned")));

        verify(authenticationService).checkUserBanStatus(eq("banneduser"));
    }
} 