package dev.idachev.userservice.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.idachev.userservice.config.JwtConfig;
import dev.idachev.userservice.exception.InvalidTokenException;
import dev.idachev.userservice.exception.ResourceNotFoundException;
import dev.idachev.userservice.exception.UserAlreadyExistsException;
import dev.idachev.userservice.model.User;
import dev.idachev.userservice.security.UserPrincipal;
import dev.idachev.userservice.service.AuthenticationService;
import dev.idachev.userservice.service.TokenBlacklistService;
import dev.idachev.userservice.service.UserDetailsService;
import dev.idachev.userservice.web.dto.*;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.test.context.support.WithUserDetails;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.BDDMockito.*;
import static org.mockito.Mockito.mock;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(
        controllers = AuthController.class
)
@DisplayName("AuthController Tests")
class AuthControllerApiTest {

    @TestConfiguration
    static class TestSecurityConfiguration {
        @Bean
        public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
            http
                    .authorizeHttpRequests(authorize -> authorize
                            .requestMatchers("/api/v1/auth/**").permitAll()
                            .anyRequest().authenticated()
                    )
                    .httpBasic(AbstractHttpConfigurer::disable)
                    .csrf(AbstractHttpConfigurer::disable);
            return http.build();
        }

        @Bean
        @Primary
        public UserDetailsService userDetailsService() {
            UserDetailsService mockUserDetailsService = mock(UserDetailsService.class);
            User mockUser = User.builder().username("currentuser").password("password").build();
            UserPrincipal mockPrincipal = new UserPrincipal(mockUser);
            given(mockUserDetailsService.loadUserByUsername("currentuser")).willReturn(mockPrincipal);
            return mockUserDetailsService;
        }
    }

    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private ObjectMapper objectMapper;
    @MockitoBean
    private AuthenticationService authenticationService;
    @MockitoBean
    private JwtConfig jwtConfig;
    @MockitoBean
    private TokenBlacklistService tokenBlacklistService;

    @Test
    @DisplayName("POST /signin - Success")
    void signin_Success() throws Exception {
        SignInRequest signInRequest = new SignInRequest("testuser", "password");
        AuthResponse mockAuthResponse = AuthResponse.builder()
                .token("dummy-jwt-token").success(true).message("Authentication successful").build();

        given(authenticationService.signIn(any(SignInRequest.class))).willReturn(mockAuthResponse);

        mockMvc.perform(post("/api/v1/auth/signin")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(signInRequest)))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.token").value(mockAuthResponse.getToken()))
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.message").value("Authentication successful"));
    }

    @Test
    @DisplayName("POST /signup - Success")
    void signup_Success() throws Exception {
        RegisterRequest registerRequest = new RegisterRequest("newuser", "newuser@example.com", "Password123!");
        AuthResponse mockAuthResponse = AuthResponse.builder()
                .token("signup-jwt-token")
                .success(true)
                .message("User signed up successfully")
                .username(registerRequest.username())
                .email(registerRequest.email())
                .build();

        given(authenticationService.register(any(RegisterRequest.class))).willReturn(mockAuthResponse);

        mockMvc.perform(post("/api/v1/auth/signup")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(registerRequest)))
                .andExpect(status().isCreated())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.token").value(mockAuthResponse.getToken()))
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.message").value("User signed up successfully"))
                .andExpect(jsonPath("$.username").value(registerRequest.username()))
                .andExpect(jsonPath("$.email").value(registerRequest.email()));
    }

    @Test
    @DisplayName("POST /refresh-token - Success")
    void refreshToken_Success() throws Exception {
        String refreshToken = "valid-refresh-token";
        String authHeader = "Bearer " + refreshToken;
        AuthResponse mockAuthResponse = AuthResponse.builder()
                .token("new-access-token").success(true).message("Token refreshed successfully").build();

        given(authenticationService.refreshToken(authHeader)).willReturn(mockAuthResponse);

        mockMvc.perform(post("/api/v1/auth/refresh-token")
                        .with(csrf())
                        .header("Authorization", authHeader))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.token").value(mockAuthResponse.getToken()))
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.message").value("Token refreshed successfully"));
    }

    @Test
    @DisplayName("POST /logout - Success")
    void logout_Success() throws Exception {
        String authToken = "valid-auth-token";
        String authHeader = "Bearer " + authToken;

        mockMvc.perform(post("/api/v1/auth/logout")
                        .with(csrf())
                        .header("Authorization", authHeader))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.message").value("Successfully logged out"));

        then(authenticationService).should().logout(authHeader);
    }

    @Test
    @DisplayName("POST /change-username - Success")
    @WithUserDetails("currentuser")
    void changeUsername_Success() throws Exception {
        ProfileUpdateRequest request = new ProfileUpdateRequest("newusername", "currentpassword");
        String currentUsername = "currentuser";

        mockMvc.perform(post("/api/v1/auth/change-username")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.message").value("Username updated successfully"));

        then(authenticationService).should().changeUsername(
                eq(currentUsername),
                eq(request.getUsername()),
                eq(request.getCurrentPassword())
        );
    }

    @Test
    @DisplayName("GET /check-status - Success")
    void checkUserStatus_Success() throws Exception {
        String identifier = "user@example.com";
        UserStatusResponse mockResponse = UserStatusResponse.builder()
                .username("testuser").enabled(true).banned(false).build();

        given(authenticationService.checkUserStatus(identifier)).willReturn(mockResponse);

        mockMvc.perform(get("/api/v1/auth/check-status")
                        .param("identifier", identifier))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.username").value(mockResponse.getUsername()))
                .andExpect(jsonPath("$.enabled").value(mockResponse.isEnabled()))
                .andExpect(jsonPath("$.banned").value(mockResponse.isBanned()));

        then(authenticationService).should().checkUserStatus(identifier);
    }

    // --- Failure Cases ---

    @Test
    @DisplayName("POST /signin - Failure (Invalid Credentials)")
    void signin_Failure_InvalidCredentials() throws Exception {
        SignInRequest signInRequest = new SignInRequest("testuser", "wrongpassword");

        // Simulate service throwing BadCredentialsException (typically results in 401)
        given(authenticationService.signIn(any(SignInRequest.class)))
                .willThrow(new BadCredentialsException("Bad credentials")); // Changed exception type

        mockMvc.perform(post("/api/v1/auth/signin")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(signInRequest)))
                .andExpect(status().isUnauthorized()); // Expect 401 Unauthorized
        // TODO: Assert response body if GlobalExceptionHandler returns one
    }

    @Test
    @DisplayName("POST /signup - Failure (User Exists)")
    void signup_Failure_UserExists() throws Exception {
        // Use a valid password format even for failure cases to pass validation first
        RegisterRequest registerRequest = new RegisterRequest("existingUser", "existing@example.com", "Password123!"); // Updated password

        // Simulate service throwing UserAlreadyExistsException
        given(authenticationService.register(any(RegisterRequest.class)))
                .willThrow(new UserAlreadyExistsException("Username 'existingUser' is already taken."));

        mockMvc.perform(post("/api/v1/auth/signup")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(registerRequest)))
                .andExpect(status().isConflict()); // Expect 409 Conflict
        // TODO: Assert response body if GlobalExceptionHandler returns one
    }

    @Test
    @DisplayName("POST /refresh-token - Failure (Invalid Token)")
    void refreshToken_Failure_InvalidToken() throws Exception {
        String invalidTokenHeader = "Bearer invalid-token";

        // Simulate service throwing InvalidTokenException
        given(authenticationService.refreshToken(anyString()))
                .willThrow(new InvalidTokenException("Invalid refresh token"));

        mockMvc.perform(post("/api/v1/auth/refresh-token")
                        .with(csrf())
                        .header("Authorization", invalidTokenHeader))
                .andExpect(status().isUnauthorized()); // Expect 401 Unauthorized
        // TODO: Assert response body if GlobalExceptionHandler returns one
    }

    @Test
    @DisplayName("POST /logout - Failure (Invalid Token)")
    void logout_Failure_InvalidToken() throws Exception {
        String invalidTokenHeader = "Bearer invalid-token";

        // Simulate service throwing InvalidTokenException on logout
        // Need to use BDDMockito.willThrow for void methods
        willThrow(new InvalidTokenException("Invalid token"))
                .given(authenticationService).logout(anyString());

        mockMvc.perform(post("/api/v1/auth/logout")
                        .with(csrf())
                        .header("Authorization", invalidTokenHeader))
                .andExpect(status().isUnauthorized()); // Expect 401 Unauthorized
        // TODO: Assert response body if GlobalExceptionHandler returns one
    }

    @Test
    @DisplayName("POST /change-username - Failure (Incorrect Password)")
    @WithUserDetails("currentuser")
    void changeUsername_Failure_IncorrectPassword() throws Exception {
        ProfileUpdateRequest request = new ProfileUpdateRequest("newusername", "wrongCurrentPassword");
        String currentUsername = "currentuser";

        // Simulate service throwing BadCredentialsException (maps to 401)
        willThrow(new BadCredentialsException("Incorrect current password")) // Changed exception type
                .given(authenticationService).changeUsername(eq(currentUsername), anyString(), eq("wrongCurrentPassword"));

        mockMvc.perform(post("/api/v1/auth/change-username")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized()); // Expect 401 Unauthorized
    }

    @Test
    @DisplayName("POST /change-username - Failure (Username Taken)")
    @WithUserDetails("currentuser")
    void changeUsername_Failure_UsernameTaken() throws Exception {
        ProfileUpdateRequest request = new ProfileUpdateRequest("existingUsername", "correctCurrentPassword");
        String currentUsername = "currentuser";

        // Simulate service throwing UserAlreadyExistsException
        willThrow(new UserAlreadyExistsException("Username 'existingUsername' is already taken."))
                .given(authenticationService).changeUsername(eq(currentUsername), eq("existingUsername"), anyString());

        mockMvc.perform(post("/api/v1/auth/change-username")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isConflict()); // Expect 409 Conflict
    }

    @Test
    @DisplayName("GET /check-status - Failure (Not Found)")
    void checkUserStatus_Failure_NotFound() throws Exception {
        String identifier = "nonexistent@example.com";

        // Simulate service throwing ResourceNotFoundException
        given(authenticationService.checkUserStatus(identifier))
                .willThrow(new ResourceNotFoundException("User not found with identifier: " + identifier));

        mockMvc.perform(get("/api/v1/auth/check-status")
                        .param("identifier", identifier))
                .andExpect(status().isNotFound()); // Expect 404 Not Found
    }
} 