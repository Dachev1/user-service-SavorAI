package dev.idachev.userservice.integration;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.idachev.userservice.model.Role;
import dev.idachev.userservice.model.User;
import dev.idachev.userservice.repository.UserRepository;
import dev.idachev.userservice.web.dto.PasswordChangeRequest;
import dev.idachev.userservice.web.dto.SignInRequest;
import dev.idachev.userservice.service.TokenBlacklistService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Transactional
class ProfileITest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    // Mock TokenBlacklistService to satisfy context creation (even if not used directly)
    @MockitoBean
    private TokenBlacklistService tokenBlacklistService;

    // Simple AuthResponse for parsing sign-in results
    private static class AuthResponse {
        public String token;
        public String getToken() { return token; }
        public void setToken(String token) { this.token = token; }
    }

    // --- Helper Methods ---

    private User createUser(String username, String email, String password, Role role, boolean enabled) {
        // Encode the password before saving
        String encodedPassword = passwordEncoder.encode(password);
        User user = User.builder()
                .username(username)
                .email(email)
                .password(encodedPassword) // Use encoded password
                .role(role)
                .enabled(enabled)
                .build();
        return userRepository.save(user);
    }

    private User createDefaultVerifiedUser(String username, String email, String password) {
        return createUser(username, email, password, Role.USER, true);
    }

    // Helper to get auth token (signs up if needed, then signs in)
    private String getAuthToken(String username, String email, String password) throws Exception {
         // Ensure user exists (create if not)
        userRepository.findByUsername(username).orElseGet(() -> 
            createDefaultVerifiedUser(username, email, password)
        );

        // Sign in
        SignInRequest signInRequest = new SignInRequest(username, password);
        String responseString = mockMvc.perform(post("/api/v1/auth/signin")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(signInRequest)))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        AuthResponse authResponse = objectMapper.readValue(responseString, AuthResponse.class);
        return authResponse.getToken();
    }

    // --- Get Profile Tests ---

    @Test
    void givenAuthenticatedUser_whenGetProfileMe_thenOkAndProfileReturned() throws Exception {
        // Given: An authenticated user
        String username = "profileuser";
        String email = "profile@example.com";
        String password = "password123";
        String authToken = getAuthToken(username, email, password);

        // When: Get profile endpoint is called
        mockMvc.perform(get("/api/v1/profile/me")
                        .header("Authorization", "Bearer " + authToken))
                // Then: Response is OK, profile data returned
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.username").value(username))
                .andExpect(jsonPath("$.email").value(email))
                .andExpect(jsonPath("$.role").value(Role.USER.name()))
                .andExpect(jsonPath("$.enabled").value(true));
    }

    @Test
    void givenUnauthenticatedUser_whenGetProfileMe_thenUnauthorized() throws Exception {
        // When: Get profile endpoint without authentication
        mockMvc.perform(get("/api/v1/profile/me"))
                // Then: Response is 401 Unauthorized
                .andExpect(status().isUnauthorized());
    }

    // --- Delete Profile Tests ---

    @Test
    void givenAuthenticatedUser_whenDeleteProfileMe_thenOkAndUserDeleted() throws Exception {
        // Given: An authenticated user
        String username = "deleteuser";
        String email = "delete@example.com";
        String password = "password123";
        String authToken = getAuthToken(username, email, password);

        // Find the user ID before deletion
        User userToDelete = userRepository.findByUsername(username).orElseThrow();
        UUID userId = userToDelete.getId();

        // When: Delete profile endpoint is called
        mockMvc.perform(delete("/api/v1/profile/me")
                        .header("Authorization", "Bearer " + authToken))
                // Then: Response is OK
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.message").value("Account successfully deleted"));

        // And then: Verify user deleted from DB
        assertThat(userRepository.findById(userId)).isNotPresent();
        assertThat(userRepository.findByUsername(username)).isNotPresent();
    }

    @Test
    void givenUnauthenticatedUser_whenDeleteProfileMe_thenUnauthorized() throws Exception {
        // When: Delete profile endpoint without authentication
        mockMvc.perform(delete("/api/v1/profile/me"))
                // Then: Response is 401 Unauthorized
                .andExpect(status().isUnauthorized());
    }

    // --- Change Password Tests ---

    @Test
    void givenValidRequest_whenChangePassword_thenOk() throws Exception {
        // Given: An authenticated user and valid password change request
        String username = "pwchangeuser";
        String email = "pwchange@example.com";
        String currentPassword = "password123";
        String newPassword = "newPassword456";
        String authToken = getAuthToken(username, email, currentPassword);

        // And given: A valid password change request
        PasswordChangeRequest request = new PasswordChangeRequest(currentPassword, newPassword, newPassword);

        // When: Change password endpoint is called
        mockMvc.perform(post("/api/v1/profile/password")
                        .header("Authorization", "Bearer " + authToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                // Then: Response is OK
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.message").value("Password changed successfully"));

        // And then: Verify user can sign in with the new password
        SignInRequest signInRequest = new SignInRequest(username, newPassword);
        mockMvc.perform(post("/api/v1/auth/signin")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(signInRequest)))
                .andExpect(status().isOk());
    }

    @Test
    void givenIncorrectCurrentPassword_whenChangePassword_thenBadRequest() throws Exception {
        // Given: Authenticated user, request with incorrect current password
        String username = "pwchangeuser_wrongpw";
        String email = "pwchangewrong@example.com";
        String currentPassword = "password123";
        String wrongCurrentPassword = "wrongpassword";
        String newPassword = "newPassword456";
        String authToken = getAuthToken(username, email, currentPassword);

        // And given: A password change request with the wrong current password
        PasswordChangeRequest request = new PasswordChangeRequest(wrongCurrentPassword, newPassword, newPassword);

        // When: Change password endpoint is called
        mockMvc.perform(post("/api/v1/profile/password")
                        .header("Authorization", "Bearer " + authToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                // Then: Response is 400 Bad Request
                .andExpect(status().isBadRequest());
    }

    @Test
    void givenNewPasswordsMismatch_whenChangePassword_thenBadRequest() throws Exception {
        // Given: Authenticated user, request with mismatched new passwords
        String username = "pwchangeuser_mismatch";
        String email = "pwchangemismatch@example.com";
        String currentPassword = "password123";
        String newPassword1 = "newPassword456";
        String newPassword2 = "differentPassword789";
        String authToken = getAuthToken(username, email, currentPassword);

        // And given: A password change request where new passwords don't match
        PasswordChangeRequest request = new PasswordChangeRequest(currentPassword, newPassword1, newPassword2);

        // When: Change password endpoint is called
        mockMvc.perform(post("/api/v1/profile/password")
                        .header("Authorization", "Bearer " + authToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                // Then: Response is 400 Bad Request
                .andExpect(status().isBadRequest());
    }
    
    @Test
    void givenBlankPassword_whenChangePassword_thenBadRequest() throws Exception {
        // Given: Authenticated user, request with blank new password
        String username = "pwchangeuser_blank";
        String email = "pwchangeblank@example.com";
        String currentPassword = "password123";
        String newPassword = ""; // Blank password
        String authToken = getAuthToken(username, email, currentPassword);

        // And given: A password change request with blank new password
        PasswordChangeRequest request = new PasswordChangeRequest(currentPassword, newPassword, newPassword);

        // When: Change password endpoint is called
        mockMvc.perform(post("/api/v1/profile/password")
                        .header("Authorization", "Bearer " + authToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                // Then: Response is 400 Bad Request
                .andExpect(status().isBadRequest());
    }

    @Test
    void givenUnauthenticatedUser_whenChangePassword_thenUnauthorized() throws Exception {
        // Given: A password change request (user details don't matter here)
        PasswordChangeRequest request = new PasswordChangeRequest("any", "new", "new");

        // When: Change password endpoint without authentication
        mockMvc.perform(post("/api/v1/profile/password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                // Then: Response is 401 Unauthorized
                .andExpect(status().isUnauthorized());
    }

} 