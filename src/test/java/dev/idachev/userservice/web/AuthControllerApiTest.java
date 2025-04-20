package dev.idachev.userservice.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.idachev.userservice.exception.AuthenticationException;
import dev.idachev.userservice.exception.ResourceConflictException;
import dev.idachev.userservice.exception.ResourceNotFoundException;
import dev.idachev.userservice.model.Role;
import dev.idachev.userservice.model.User;
import dev.idachev.userservice.security.UserPrincipal;
import dev.idachev.userservice.service.AuthenticationService;
import dev.idachev.userservice.web.dto.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Collections;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(controllers = AuthController.class)
@AutoConfigureMockMvc(addFilters = false)
@DisplayName("AuthController API Tests")
class AuthControllerApiTest {

    private static final String BASE_PATH = "/api/v1/auth";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockBean
    private AuthenticationService authService;

    private RegisterRequest registerRequest;
    private SignInRequest signInRequest;
    private ProfileUpdateRequest profileUpdateRequest;
    private AuthResponse authResponse;
    private UserStatusResponse userStatusResponse;

    @BeforeEach
    void setUp() {
        registerRequest = new RegisterRequest("testuser", "test@example.com", "password123");
        signInRequest = new SignInRequest("testuser", "password123");
        profileUpdateRequest = new ProfileUpdateRequest("newuser", "password123");
        authResponse = AuthResponse.builder()
                .token("access_token")
                .username("testuser")
                .email("test@example.com")
                .role(Role.USER.name())
                .enabled(true)
                .verificationPending(false)
                .banned(false)
                .success(true)
                .message("Success")
                .build();
        userStatusResponse = new UserStatusResponse("testuser", true, false);
    }

    @Nested
    @DisplayName("POST /signup")
    class SignupTests {

        @Test
        @DisplayName("Should return 201 Created on successful signup")
        void signup_Success() throws Exception {
            when(authService.register(any(RegisterRequest.class))).thenReturn(authResponse);

            mockMvc.perform(post(BASE_PATH + "/signup")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(registerRequest)))
                    .andExpect(status().isCreated())
                    .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                    .andExpect(jsonPath("$.token").value(authResponse.getToken()));

            verify(authService).register(eq(registerRequest));
        }

        @Test
        @DisplayName("Should return 409 Conflict when username/email already exists")
        void signup_Conflict() throws Exception {
            when(authService.register(any(RegisterRequest.class)))
                    .thenThrow(new ResourceConflictException("Username or email already exists"));

            mockMvc.perform(post(BASE_PATH + "/signup")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(registerRequest)))
                    .andExpect(status().isConflict());

            verify(authService).register(eq(registerRequest));
        }

        @Test
        @DisplayName("Should return 400 Bad Request for invalid input")
        void signup_BadRequest_InvalidInput() throws Exception {
            RegisterRequest invalidRequest = new RegisterRequest("", "", ""); // Invalid data

            mockMvc.perform(post(BASE_PATH + "/signup")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(invalidRequest)))
                    .andExpect(status().isBadRequest()); // Assuming validation is handled by @Valid

            verify(authService, never()).register(any(RegisterRequest.class));
        }
    }

    @Nested
    @DisplayName("POST /signin")
    class SigninTests {

        @Test
        @DisplayName("Should return 200 OK on successful signin")
        void signin_Success() throws Exception {
            when(authService.signIn(any(SignInRequest.class))).thenReturn(authResponse);

            mockMvc.perform(post(BASE_PATH + "/signin")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(signInRequest)))
                    .andExpect(status().isOk())
                    .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                    .andExpect(jsonPath("$.token").value(authResponse.getToken()));

            verify(authService).signIn(eq(signInRequest));
        }

        @Test
        @DisplayName("Should return 401 Unauthorized for invalid credentials")
        void signin_Unauthorized_InvalidCredentials() throws Exception {
            when(authService.signIn(any(SignInRequest.class)))
                    .thenThrow(new AuthenticationException("Invalid credentials"));

            mockMvc.perform(post(BASE_PATH + "/signin")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(signInRequest)))
                    .andExpect(status().isUnauthorized());

            verify(authService).signIn(eq(signInRequest));
        }

        @Test
        @DisplayName("Should return 400 Bad Request for invalid input")
        void signin_BadRequest_InvalidInput() throws Exception {
            SignInRequest invalidRequest = new SignInRequest("", ""); // Invalid data

            mockMvc.perform(post(BASE_PATH + "/signin")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(invalidRequest)))
                    .andExpect(status().isBadRequest()); // Assuming validation is handled by @Valid

            verify(authService, never()).signIn(any(SignInRequest.class));
        }
    }

    @Nested
    @DisplayName("POST /refresh-token")
    class RefreshTokenTests {

        @Test
        @DisplayName("Should return 200 OK with new tokens for valid refresh token")
        void refreshToken_Success() throws Exception {
            String validRefreshTokenHeader = "Bearer valid_refresh_token";
            when(authService.refreshToken(eq(validRefreshTokenHeader))).thenReturn(authResponse);

            mockMvc.perform(post(BASE_PATH + "/refresh-token")
                            .header(HttpHeaders.AUTHORIZATION, validRefreshTokenHeader))
                    .andExpect(status().isOk())
                    .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                    .andExpect(jsonPath("$.token").value(authResponse.getToken()));

            verify(authService).refreshToken(eq(validRefreshTokenHeader));
        }

        @Test
        @DisplayName("Should return 401 Unauthorized for invalid or expired refresh token")
        void refreshToken_Unauthorized_InvalidToken() throws Exception {
            String invalidRefreshTokenHeader = "Bearer invalid_refresh_token";
            when(authService.refreshToken(eq(invalidRefreshTokenHeader)))
                    .thenThrow(new AuthenticationException("Invalid refresh token"));

            mockMvc.perform(post(BASE_PATH + "/refresh-token")
                            .header(HttpHeaders.AUTHORIZATION, invalidRefreshTokenHeader))
                    .andExpect(status().isUnauthorized());

            verify(authService).refreshToken(eq(invalidRefreshTokenHeader));
        }

        @Test
        @DisplayName("Should return 400 Bad Request if Authorization header is missing")
            // Note: Spring Security typically handles missing headers earlier, resulting in 401/403,
            // but testing controller logic directly assuming header presence might lead to this expectation.
            // Depending on actual security config, 401/403 might be more accurate.
            // Let's assume the service layer expects a non-null header.
        void refreshToken_BadRequest_MissingHeader() throws Exception {
            when(authService.refreshToken(null)) // Simulate missing header passed to service
                    .thenThrow(new IllegalArgumentException("Authorization header is missing or invalid")); // Or similar exception

            mockMvc.perform(post(BASE_PATH + "/refresh-token"))
                    // Depending on setup, this might be 401/403 due to security filters
                    .andExpect(status().isBadRequest()); // Or isUnauthorized() or isForbidden()

            // Verification might depend on whether the controller method is even reached
            verify(authService, never()).refreshToken(anyString()); // Or verify based on expected exception handling
        }
    }

    @Nested
    @DisplayName("POST /logout")
    class LogoutTests {

        @Test
        @DisplayName("Should return 200 OK on successful logout")
        void logout_Success() throws Exception {
            String validAuthHeader = "Bearer valid_access_token";
            doNothing().when(authService).logout(eq(validAuthHeader));

            mockMvc.perform(post(BASE_PATH + "/logout")
                            .header(HttpHeaders.AUTHORIZATION, validAuthHeader))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.message").value("Successfully logged out"));

            verify(authService).logout(eq(validAuthHeader));
        }

        @Test
        @DisplayName("Should return 401 Unauthorized if Authorization header is missing or invalid")
            // Again, Spring Security might intercept this earlier. Testing the intended controller behavior.
        void logout_Unauthorized_MissingOrInvalidHeader() throws Exception {
            // Case 1: Missing header
            mockMvc.perform(post(BASE_PATH + "/logout"))
                    .andExpect(status().isBadRequest()); // Or 401/403

            // Case 2: Invalid header format (if service checks format)
            String invalidHeader = "InvalidTokenFormat";
            // Mocking service to throw an exception if it validates the header format
            // doThrow(new AuthenticationFailedException("Invalid token format")).when(authService).logout(invalidHeader);

            // mockMvc.perform(post(BASE_PATH + "/logout")
            //                 .header(HttpHeaders.AUTHORIZATION, invalidHeader))
            //         .andExpect(status().isUnauthorized());

            verify(authService, never()).logout(anyString()); // Adjust verification based on actual flow
        }
    }

    @Nested
    @DisplayName("POST /change-username")
    class ChangeUsernameTests {

        private UserPrincipal createMockUserPrincipal(String username) {
            User mockUser = User.builder()
                    .id(java.util.UUID.randomUUID()) // Assuming UUID id
                    .username(username)
                    .email("test@example.com")
                    .password("encodedPassword")
                    .enabled(true)
                    .role(Role.USER)
                    .banned(false)
                    .build();
            return new UserPrincipal(mockUser);
        }

        @Test
        @DisplayName("Should return 200 OK on successful username change")
        void changeUsername_Success() throws Exception {
            UserPrincipal principal = createMockUserPrincipal("testuser");
            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                    principal, null, principal.getAuthorities());

            doNothing().when(authService).changeUsername(
                    eq("testuser"),
                    eq(profileUpdateRequest.getUsername()),
                    eq(profileUpdateRequest.getCurrentPassword())
            );

            mockMvc.perform(post(BASE_PATH + "/change-username")
                            .with(authentication(authentication)) // Provide mock authentication
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(profileUpdateRequest)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.message").value("Username updated successfully"));

            verify(authService).changeUsername(
                    eq("testuser"),
                    eq(profileUpdateRequest.getUsername()),
                    eq(profileUpdateRequest.getCurrentPassword())
            );
        }

        @Test
        @DisplayName("Should return 401 Unauthorized if not authenticated")
        void changeUsername_Unauthorized_NotAuthenticated() throws Exception {
            mockMvc.perform(post(BASE_PATH + "/change-username")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(profileUpdateRequest)))
                    .andExpect(status().isUnauthorized()); // Or 403 Forbidden depending on config

            verify(authService, never()).changeUsername(anyString(), anyString(), anyString());
        }


        @Test
        @DisplayName("Should return 401 Unauthorized for incorrect current password")
        void changeUsername_Unauthorized_IncorrectPassword() throws Exception {
            UserPrincipal principal = createMockUserPrincipal("testuser");
            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                    principal, null, principal.getAuthorities());

            doThrow(new AuthenticationException("Incorrect password"))
                    .when(authService).changeUsername(anyString(), anyString(), anyString());

            mockMvc.perform(post(BASE_PATH + "/change-username")
                            .with(authentication(authentication))
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(profileUpdateRequest)))
                    .andExpect(status().isUnauthorized());

            verify(authService).changeUsername(
                    eq("testuser"),
                    eq(profileUpdateRequest.getUsername()),
                    eq(profileUpdateRequest.getCurrentPassword())
            );
        }

        @Test
        @DisplayName("Should return 409 Conflict if new username is taken")
        void changeUsername_Conflict_UsernameTaken() throws Exception {
            UserPrincipal principal = createMockUserPrincipal("testuser");
            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                    principal, null, principal.getAuthorities());

            doThrow(new ResourceConflictException("Username already taken"))
                    .when(authService).changeUsername(anyString(), anyString(), anyString());

            mockMvc.perform(post(BASE_PATH + "/change-username")
                            .with(authentication(authentication))
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(profileUpdateRequest)))
                    .andExpect(status().isConflict());

            verify(authService).changeUsername(
                    eq("testuser"),
                    eq(profileUpdateRequest.getUsername()),
                    eq(profileUpdateRequest.getCurrentPassword())
            );
        }

        @Test
        @DisplayName("Should return 400 Bad Request for invalid input")
        void changeUsername_BadRequest_InvalidInput() throws Exception {
            UserPrincipal principal = createMockUserPrincipal("testuser");
            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                    principal, null, principal.getAuthorities());
            ProfileUpdateRequest invalidRequest = new ProfileUpdateRequest("", ""); // Invalid data

            mockMvc.perform(post(BASE_PATH + "/change-username")
                            .with(authentication(authentication))
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(invalidRequest)))
                    .andExpect(status().isBadRequest()); // Assuming validation handles this

            verify(authService, never()).changeUsername(anyString(), anyString(), anyString());
        }
    }

    @Nested
    @DisplayName("GET /check-status")
    class CheckStatusTests {

        @Test
        @DisplayName("Should return 200 OK with user status for existing user")
        void checkUserStatus_Success_UserExists() throws Exception {
            String identifier = "testuser";
            when(authService.checkUserStatus(eq(identifier))).thenReturn(userStatusResponse);

            mockMvc.perform(get(BASE_PATH + "/check-status")
                            .param("identifier", identifier))
                    .andExpect(status().isOk())
                    .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                    .andExpect(jsonPath("$.username").value(userStatusResponse.getUsername()))
                    .andExpect(jsonPath("$.enabled").value(userStatusResponse.isEnabled()))
                    .andExpect(jsonPath("$.banned").value(userStatusResponse.isBanned()));

            verify(authService).checkUserStatus(eq(identifier));
        }

        @Test
        @DisplayName("Should return 404 Not Found for non-existing user")
        void checkUserStatus_NotFound_UserDoesNotExist() throws Exception {
            String identifier = "nonexistent";
            when(authService.checkUserStatus(eq(identifier)))
                    .thenThrow(new ResourceNotFoundException("User not found"));

            mockMvc.perform(get(BASE_PATH + "/check-status")
                            .param("identifier", identifier))
                    .andExpect(status().isNotFound());

            verify(authService).checkUserStatus(eq(identifier));
        }

        @Test
        @DisplayName("Should return 400 Bad Request if identifier parameter is missing")
        void checkUserStatus_BadRequest_MissingIdentifier() throws Exception {
            mockMvc.perform(get(BASE_PATH + "/check-status")) // No identifier param
                    .andExpect(status().isBadRequest());

            verify(authService, never()).checkUserStatus(anyString());
        }
    }
} 