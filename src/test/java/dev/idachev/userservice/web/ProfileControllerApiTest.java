package dev.idachev.userservice.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.idachev.userservice.config.JwtConfig;
import dev.idachev.userservice.model.Role;
import dev.idachev.userservice.model.User;
import dev.idachev.userservice.security.UserPrincipal;
import dev.idachev.userservice.service.ProfileService;
import dev.idachev.userservice.service.TokenBlacklistService;
import dev.idachev.userservice.service.UserDetailsService;
import dev.idachev.userservice.web.dto.PasswordChangeRequest;
import dev.idachev.userservice.web.dto.UserResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.test.context.support.WithUserDetails;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.time.LocalDateTime;
import java.util.UUID;

import static org.mockito.BDDMockito.*;
import static org.mockito.Mockito.mock;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(controllers = ProfileController.class,
        excludeAutoConfiguration = {UserDetailsServiceAutoConfiguration.class})
@DisplayName("ProfileController Tests")
class ProfileControllerApiTest {

    private static final String TEST_USERNAME = "testuser";

    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private ObjectMapper objectMapper;
    @MockitoBean
    private ProfileService profileService;
    @MockitoBean
    private JwtConfig jwtConfig;
    @MockitoBean
    private TokenBlacklistService tokenBlacklistService;

    @TestConfiguration
    static class TestSecurityConfiguration {
        @Bean
        @Primary
        public UserDetailsService userDetailsService() {
            UserPrincipal userPrincipal = new UserPrincipal(User.builder()
                    .id(UUID.randomUUID())
                    .username(TEST_USERNAME)
                    .email("test@example.com")
                    .password("password")
                    .role(Role.USER)
                    .enabled(true)
                    .build());
            UserDetailsService mockService = mock(UserDetailsService.class);
            when(mockService.loadUserByUsername(TEST_USERNAME)).thenReturn(userPrincipal);
            return mockService;
        }
    }

    @BeforeEach
    void setUp() {
        // No need to mock userDetailsService here anymore
    }

    @Test
    @DisplayName("GET /me - Success")
    @WithUserDetails(value = TEST_USERNAME)
    void getCurrentUserProfile_Success() throws Exception {
        UserResponse mockUserResponse = UserResponse.builder()
                .username(TEST_USERNAME).email("test@example.com").role("USER")
                .enabled(true).lastLogin(LocalDateTime.now()).build();

        given(profileService.getUserInfoByUsername(TEST_USERNAME)).willReturn(mockUserResponse);

        mockMvc.perform(get("/api/v1/profile/me"))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.username").value(TEST_USERNAME))
                .andExpect(jsonPath("$.email").value(mockUserResponse.getEmail()));

        then(profileService).should().getUserInfoByUsername(TEST_USERNAME);
    }

    @Test
    @DisplayName("DELETE /me - Success")
    @WithUserDetails(value = TEST_USERNAME)
    void deleteCurrentUserAccount_Success() throws Exception {
        mockMvc.perform(delete("/api/v1/profile/me")
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.message").value("Account successfully deleted"));

        then(profileService).should().deleteAccount(TEST_USERNAME);
    }

    @Test
    @DisplayName("POST /password - Success")
    @WithUserDetails(value = TEST_USERNAME)
    void changeCurrentUserPassword_Success() throws Exception {
        PasswordChangeRequest request = new PasswordChangeRequest("oldPassword123", "newPassword456", "newPassword456");

        mockMvc.perform(post("/api/v1/profile/password")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.message").value("Password changed successfully"));

        then(profileService).should().changePassword(TEST_USERNAME, request);
    }

    // --- Failure Cases ---

    @Test
    @DisplayName("GET /me - Failure (Unauthorized)")
    void getCurrentUserProfile_Failure_Unauthorized() throws Exception {
        mockMvc.perform(get("/api/v1/profile/me"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("DELETE /me - Failure (Unauthorized)")
    void deleteCurrentUserAccount_Failure_Unauthorized() throws Exception {
        mockMvc.perform(delete("/api/v1/profile/me")
                        .with(csrf()))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("POST /password - Failure (Unauthorized)")
    void changeCurrentUserPassword_Failure_Unauthorized() throws Exception {
        PasswordChangeRequest request = new PasswordChangeRequest("any", "new", "new");

        mockMvc.perform(post("/api/v1/profile/password")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("POST /password - Failure (Incorrect Current Password)")
    @WithUserDetails(value = TEST_USERNAME)
    void changeCurrentUserPassword_Failure_IncorrectPassword() throws Exception {
        PasswordChangeRequest request = new PasswordChangeRequest("wrongOldPassword", "newPass", "newPass");

        willThrow(new BadCredentialsException("Incorrect current password"))
                .given(profileService).changePassword(eq(TEST_USERNAME), eq(request));

        mockMvc.perform(post("/api/v1/profile/password")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("POST /password - Failure (Password Mismatch/Validation)")
    @WithUserDetails(value = TEST_USERNAME)
    void changeCurrentUserPassword_Failure_Validation() throws Exception {
        PasswordChangeRequest request = new PasswordChangeRequest("oldPassword", "newPass1", "newPass2");

        willThrow(new IllegalArgumentException("New passwords do not match"))
                .given(profileService).changePassword(eq(TEST_USERNAME), eq(request));

        mockMvc.perform(post("/api/v1/profile/password")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest());
    }
} 