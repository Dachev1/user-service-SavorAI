package dev.idachev.userservice.integration;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.idachev.userservice.model.Role;
import dev.idachev.userservice.model.User;
import dev.idachev.userservice.repository.UserRepository;
import dev.idachev.userservice.service.TokenBlacklistService;
import dev.idachev.userservice.web.dto.SignInRequest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
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
class UserITest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @MockitoBean
    private TokenBlacklistService tokenBlacklistService;

    // Simplified DTO for parsing auth response
    private static class AuthResponse {
        public String token;

        public String getToken() {
            return token;
        }

        public void setToken(String token) {
            this.token = token;
        }
    }

    // --- Helper Methods ---

    // Creates user and returns Bearer token
    private String getUserAuthToken(String username, String email, String password) throws Exception {
        createUser(username, email, password, Role.USER, true);
        return signInAndGetToken(username, password);
    }

    // Creates admin user and returns Bearer token
    private String getAdminAuthToken(String username, String email, String password) throws Exception {
        createAdminUser(username, email, password);
        return signInAndGetToken(username, password);
    }

    // Performs sign-in and extracts token
    private String signInAndGetToken(String username, String password) throws Exception {
        SignInRequest signInRequest = new SignInRequest(username, password);
        String responseString = mockMvc.perform(post("/api/v1/auth/signin")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(signInRequest)))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        AuthResponse authResponse = objectMapper.readValue(responseString, AuthResponse.class);
        return authResponse.getToken();
    }

    // Helper method to create a user directly
    private User createUser(String username, String email, String password, Role role, boolean enabled) {
        User user = User.builder()
                .username(username)
                .email(email)
                .password(passwordEncoder.encode(password))
                .role(role)
                .enabled(enabled)
                .build();
        return userRepository.save(user);
    }

    private User createDefaultUser(String username, String email, String password) {
        return createUser(username, email, password, Role.USER, true);
    }

    private User createAdminUser(String username, String email, String password) {
        return createUser(username, email, password, Role.ADMIN, true);
    }

    // --- Check Username Availability Tests ---

    @Test
    void givenAvailableUsername_whenCheckUsernameAvailability_thenOkAndAvailableTrue() throws Exception {
        // Given: An available username
        String availableUsername = "available_username";

        // When: Check username endpoint is called
        mockMvc.perform(get("/api/v1/users/check-username")
                        .param("username", availableUsername))
                // Then: Response is OK and available=true
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.available").value(true));
    }

    @Test
    void givenTakenUsername_whenCheckUsernameAvailability_thenOkAndAvailableFalse() throws Exception {
        // Given: An existing user
        String takenUsername = "taken_username";
        createDefaultUser(takenUsername, "taken@example.com", "password123");

        // When: Check username endpoint is called with taken username
        mockMvc.perform(get("/api/v1/users/check-username")
                        .param("username", takenUsername))
                // Then: Response is OK and available=false
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.available").value(false));
    }

    // --- Admin: Get All Users Tests ---

    @Test
    void givenAdminUser_whenGetAllUsersAdmin_thenOkAndUserListReturned() throws Exception {
        // Given: Some existing users and an admin user
        createDefaultUser("user1", "user1@example.com", "pass1");
        createDefaultUser("user2", "user2@example.com", "pass2");
        User adminUser = createAdminUser("admin1", "admin1@example.com", "adminpass");
        String adminToken = signInAndGetToken(adminUser.getUsername(), "adminpass"); // Use helper

        // When: Get all users endpoint is called by admin
        mockMvc.perform(get("/api/v1/admin/users")
                        .header("Authorization", "Bearer " + adminToken))
                // Then: Response is OK and contains the list of users
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                // Note: Adjust expected size based on initial users (admin + banned)
                .andExpect(jsonPath("$.size()").value(5)) 
                .andExpect(jsonPath("$[?(@.username == 'user1')]").exists())
                .andExpect(jsonPath("$[?(@.username == 'user2')]").exists())
                .andExpect(jsonPath("$[?(@.username == 'admin1')]").exists());
    }

    @Test
    void givenNonAdminUser_whenGetAllUsersAdmin_thenForbidden() throws Exception {
        // Given: A regular user signed in
        String regularUserToken = getUserAuthToken("user3", "user3@example.com", "pass3");

        // When: Get all users endpoint is called by regular user
        mockMvc.perform(get("/api/v1/admin/users")
                        .header("Authorization", "Bearer " + regularUserToken))
                // Then: Response is 403 Forbidden
                .andExpect(status().isForbidden());
    }

    @Test
    void givenUnauthenticatedUser_whenGetAllUsersAdmin_thenUnauthorized() throws Exception {
        // When: Get all users endpoint is called without authentication
        mockMvc.perform(get("/api/v1/admin/users"))
                // Then: Response is 401 Unauthorized
                .andExpect(status().isUnauthorized());
    }

    // --- Admin: Update User Role Tests ---

    @Test
    void givenAdminUser_whenUpdateUserRole_thenOkAndRoleUpdated() throws Exception {
        // Given: An admin and a regular user
        User admin = createAdminUser("roleadmin", "roleadmin@example.com", "adminpass");
        User userToUpdate = createDefaultUser("roleuser", "roleuser@example.com", "userpass");
        String adminToken = signInAndGetToken(admin.getUsername(), "adminpass");

        // When: Admin updates the regular user's role to ADMIN
        mockMvc.perform(put("/api/v1/admin/users/{userId}/role", userToUpdate.getId())
                        .header("Authorization", "Bearer " + adminToken)
                        .param("role", Role.ADMIN.name()))
                // Then: Response is OK, role updated
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.role").value(Role.ADMIN.name()))
                .andExpect(jsonPath("$.userId").value(userToUpdate.getId().toString()));

        // And then: Verify role update in DB
        User updatedUser = userRepository.findById(userToUpdate.getId()).orElseThrow();
        assertThat(updatedUser.getRole()).isEqualTo(Role.ADMIN);
    }

    @Test
    void givenAdminUser_whenUpdateOwnRole_thenForbidden() throws Exception {
        // Given: An admin user
        User admin = createAdminUser("roleadmin_self", "roleself@example.com", "adminpass");
        String adminToken = signInAndGetToken(admin.getUsername(), "adminpass");

        // When: Admin attempts to update their own role
        mockMvc.perform(put("/api/v1/admin/users/{userId}/role", admin.getId())
                        .header("Authorization", "Bearer " + adminToken)
                        .param("role", Role.USER.name())) // Attempt downgrade
                // Then: Response is 403 Forbidden
                .andExpect(status().isForbidden());
    }

    @Test
    void givenAdminUser_whenUpdateNonExistentUserRole_thenNotFound() throws Exception {
        // Given: An admin user
        User admin = createAdminUser("roleadmin_notfound", "rolenotfound@example.com", "adminpass");
        String adminToken = signInAndGetToken(admin.getUsername(), "adminpass");
        UUID nonExistentUserId = UUID.randomUUID();

        // When: Admin attempts update role for non-existent user
        mockMvc.perform(put("/api/v1/admin/users/{userId}/role", nonExistentUserId)
                        .header("Authorization", "Bearer " + adminToken)
                        .param("role", Role.ADMIN.name()))
                // Then: Response is 404 Not Found
                .andExpect(status().isNotFound());
    }

    @Test
    void givenAdminUser_whenUpdateRoleWithInvalidValue_thenBadRequest() throws Exception {
        // Given: An admin user and a regular user
        User admin = createAdminUser("roleadmin_invalid", "roleinvalid@example.com", "adminpass");
        User userToUpdate = createDefaultUser("roleuser_invalid", "roleuserinvalid@example.com", "userpass");
        String adminToken = signInAndGetToken(admin.getUsername(), "adminpass");

        // When: Admin attempts update with invalid role value
        mockMvc.perform(put("/api/v1/admin/users/{userId}/role", userToUpdate.getId())
                        .header("Authorization", "Bearer " + adminToken)
                        .param("role", "INVALID_ROLE_VALUE"))
                // Then: Response is 400 Bad Request
                .andExpect(status().isBadRequest());
    }

    @Test
    void givenNonAdminUser_whenUpdateUserRole_thenForbidden() throws Exception {
        // Given: Two regular users, one signed in
        User userToUpdate = createDefaultUser("roleuser_other", "roleother@example.com", "otherpass");
        String regularUserToken = getUserAuthToken("roleuser_nonadmin", "rolenonadmin@example.com", "userpass");

        // When: Regular user attempts to update another user's role
        mockMvc.perform(put("/api/v1/admin/users/{userId}/role", userToUpdate.getId())
                        .header("Authorization", "Bearer " + regularUserToken)
                        .param("role", Role.ADMIN.name()))
                // Then: Response is 403 Forbidden
                .andExpect(status().isForbidden());
    }

    // --- Admin: Toggle Ban Status Tests ---

    @Test
    void givenAdminUser_whenToggleBanOnUser_thenOkAndUserIsBanned() throws Exception {
        // Given: An admin and a regular user
        User admin = createAdminUser("banadmin", "banadmin@example.com", "adminpass");
        User userToBan = createDefaultUser("banuser", "banuser@example.com", "userpass");
        String adminToken = signInAndGetToken(admin.getUsername(), "adminpass");

        assertThat(userToBan.isBanned()).isFalse(); // Pre-condition check

        // When: Admin bans the regular user
        mockMvc.perform(put("/api/v1/admin/users/{userId}/ban", userToBan.getId())
                        .header("Authorization", "Bearer " + adminToken))
                // Then: Response is OK, user is banned
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.banned").value(true))
                .andExpect(jsonPath("$.userId").value(userToBan.getId().toString()));

        // And then: Verify ban status in DB
        User bannedUser = userRepository.findById(userToBan.getId()).orElseThrow();
        assertThat(bannedUser.isBanned()).isTrue();
    }

    @Test
    void givenAdminUser_whenToggleBanOnBannedUser_thenOkAndUserIsUnbanned() throws Exception {
        // Given: An admin and a regular user
        User admin = createAdminUser("unbanadmin", "unbanadmin@example.com", "adminpass");
        User userToManage = createUser("unbanuser", "unbanuser@example.com", "userpass", Role.USER, true);
        String adminToken = signInAndGetToken(admin.getUsername(), "adminpass");

        // First, ban the user using the endpoint
        mockMvc.perform(put("/api/v1/admin/users/{userId}/ban", userToManage.getId())
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk());

        // Verify user is now banned
        User initiallyBannedUser = userRepository.findById(userToManage.getId()).orElseThrow();
        assertThat(initiallyBannedUser.isBanned()).isTrue();

        // When: Admin unbans the user (toggles ban again)
        mockMvc.perform(put("/api/v1/admin/users/{userId}/ban", userToManage.getId())
                        .header("Authorization", "Bearer " + adminToken))
                // Then: Response is OK, user is unbanned
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.banned").value(false))
                .andExpect(jsonPath("$.userId").value(userToManage.getId().toString()));

        // And then: Verify ban status in DB
        User unbannedUser = userRepository.findById(userToManage.getId()).orElseThrow();
        assertThat(unbannedUser.isBanned()).isFalse();
    }

    @Test
    void givenAdminUser_whenToggleBanOnSelf_thenForbidden() throws Exception {
        // Given: An admin user
        User admin = createAdminUser("banselfadmin", "banself@example.com", "adminpass");
        String adminToken = signInAndGetToken(admin.getUsername(), "adminpass");

        // When: Admin attempts to ban themselves
        mockMvc.perform(put("/api/v1/admin/users/{userId}/ban", admin.getId())
                        .header("Authorization", "Bearer " + adminToken))
                // Then: Response is 403 Forbidden
                .andExpect(status().isForbidden());
    }

    @Test
    void givenAdminUser_whenToggleBanOnNonExistentUser_thenNotFound() throws Exception {
        // Given: An admin user
        User admin = createAdminUser("bannotfoundadmin", "bannotfound@example.com", "adminpass");
        String adminToken = signInAndGetToken(admin.getUsername(), "adminpass");
        UUID nonExistentUserId = UUID.randomUUID();

        // When: Admin attempts to ban non-existent user
        mockMvc.perform(put("/api/v1/admin/users/{userId}/ban", nonExistentUserId)
                        .header("Authorization", "Bearer " + adminToken))
                // Then: Response is 404 Not Found
                .andExpect(status().isNotFound());
    }

    @Test
    void givenNonAdminUser_whenToggleBan_thenForbidden() throws Exception {
        // Given: Two regular users, one signed in
        User userToBan = createDefaultUser("banotheruser", "banother@example.com", "otherpass");
        String regularUserToken = getUserAuthToken("bannonadmin", "bannonadmin@example.com", "userpass");

        // When: Regular user attempts to ban another user
        mockMvc.perform(put("/api/v1/admin/users/{userId}/ban", userToBan.getId())
                        .header("Authorization", "Bearer " + regularUserToken))
                // Then: Response is 403 Forbidden
                .andExpect(status().isForbidden());
    }

    // --- Admin: Get User By ID Tests ---

    @Test
    void givenAdminUser_whenGetUserById_thenOkAndUserReturned() throws Exception {
        // Given: An admin and a target user
        User admin = createAdminUser("getbyidadmin", "getbyidadmin@example.com", "adminpass");
        User targetUser = createDefaultUser("getbyiduser", "getbyiduser@example.com", "userpass");
        String adminToken = signInAndGetToken(admin.getUsername(), "adminpass");

        // When: Admin gets user by ID
        mockMvc.perform(get("/api/v1/admin/users/{userId}", targetUser.getId())
                        .header("Authorization", "Bearer " + adminToken))
                // Then: Response is OK and user details are returned
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.id").value(targetUser.getId().toString()))
                .andExpect(jsonPath("$.username").value(targetUser.getUsername()))
                .andExpect(jsonPath("$.email").value(targetUser.getEmail()));
                // TODO: Assert other fields if necessary
    }

    @Test
    void givenAdminUser_whenGetUserByNonExistentId_thenNotFound() throws Exception {
        // Given: An admin user
        User admin = createAdminUser("getbyidnotfoundadmin", "getbyidnotfound@example.com", "adminpass");
        String adminToken = signInAndGetToken(admin.getUsername(), "adminpass");
        UUID nonExistentUserId = UUID.randomUUID();

        // When: Admin gets user by non-existent ID
        mockMvc.perform(get("/api/v1/admin/users/{userId}", nonExistentUserId)
                        .header("Authorization", "Bearer " + adminToken))
                // Then: Response is 404 Not Found
                .andExpect(status().isNotFound());
    }

    @Test
    void givenNonAdminUser_whenGetUserById_thenForbidden() throws Exception {
        // Given: Two regular users, one signed in
        User targetUser = createDefaultUser("getbyidtarget", "getbyidtarget@example.com", "otherpass");
        String regularUserToken = getUserAuthToken("getbyidnonadmin", "getbyidnonadmin@example.com", "userpass");

        // When: Regular user attempts to get another user by ID
        mockMvc.perform(get("/api/v1/admin/users/{userId}", targetUser.getId())
                        .header("Authorization", "Bearer " + regularUserToken))
                // Then: Response is 403 Forbidden
                .andExpect(status().isForbidden());
    }

    // --- Admin: Delete User Tests ---

    @Test
    void givenAdminUser_whenDeleteUser_thenOkAndUserDeleted() throws Exception {
        // Given: An admin and a user to delete
        User admin = createAdminUser("deleteadmin", "deleteadmin@example.com", "adminpass");
        User userToDelete = createDefaultUser("deleteuser", "deleteuser@example.com", "userpass");
        String adminToken = signInAndGetToken(admin.getUsername(), "adminpass");
        UUID userIdToDelete = userToDelete.getId();

        assertThat(userRepository.existsById(userIdToDelete)).isTrue(); // Use existsById for clarity

        // When: Admin deletes the user
        mockMvc.perform(delete("/api/v1/admin/users/{userId}", userIdToDelete)
                        .header("Authorization", "Bearer " + adminToken))
                // Then: Response is OK
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.message").value("User successfully deleted"));

        // And then: Verify user is deleted from DB
        assertThat(userRepository.existsById(userIdToDelete)).isFalse();
    }

    @Test
    void givenAdminUser_whenDeleteSelf_thenForbidden() throws Exception {
        // Given: An admin user
        User admin = createAdminUser("deleteselfadmin", "deleteself@example.com", "adminpass");
        String adminToken = signInAndGetToken(admin.getUsername(), "adminpass");

        // When: Admin attempts to delete themselves
        mockMvc.perform(delete("/api/v1/admin/users/{userId}", admin.getId())
                        .header("Authorization", "Bearer " + adminToken))
                // Then: Response is 403 Forbidden
                .andExpect(status().isForbidden());
    }

    @Test
    void givenAdminUser_whenDeleteNonExistentUser_thenNotFound() throws Exception {
        // Given: An admin user
        User admin = createAdminUser("deletenotfoundadmin", "deletenotfound@example.com", "adminpass");
        String adminToken = signInAndGetToken(admin.getUsername(), "adminpass");
        UUID nonExistentUserId = UUID.randomUUID();

        // When: Admin attempts to delete non-existent user
        mockMvc.perform(delete("/api/v1/admin/users/{userId}", nonExistentUserId)
                        .header("Authorization", "Bearer " + adminToken))
                // Then: Response is 404 Not Found
                .andExpect(status().isNotFound());
    }

    @Test
    void givenNonAdminUser_whenDeleteUser_thenForbidden() throws Exception {
        // Given: Two regular users, one signed in
        User userToDelete = createDefaultUser("deleteotheruser", "deleteother@example.com", "otherpass");
        String regularUserToken = getUserAuthToken("deletenonadmin", "deletenonadmin@example.com", "userpass");

        // When: Regular user attempts to delete another user
        mockMvc.perform(delete("/api/v1/admin/users/{userId}", userToDelete.getId())
                        .header("Authorization", "Bearer " + regularUserToken))
                // Then: Response is 403 Forbidden
                .andExpect(status().isForbidden());
    }

    // --- Admin: Get User Stats Tests ---

    @Test
    void givenAdminUser_whenGetUserStats_thenOkAndStatsReturned() throws Exception {
        // Given: An admin user and various other users
        User admin = createAdminUser("statsadmin", "statsadmin@example.com", "adminpass");
        createDefaultUser("statsuser1", "statsuser1@example.com", "pass1"); // Active user
        // Removed direct creation of a banned user here - rely on initial config + admin actions
        // User userToBan = createDefaultUser("statsuser2_banned", "statsuser2@example.com", "pass2");
        // userToBan.setBanned(true); // Cannot set directly
        // userRepository.save(userToBan);

        // Count existing users from initializers + users created in this test
        // Initial: 'Ivan' (Admin, Active), 'TestBanned' (User, Banned)
        // This Test: 'statsadmin' (Admin, Active), 'statsuser1' (User, Active)
        // Total users = 4
        // Active users = 3 ('Ivan', 'statsadmin', 'statsuser1')
        // Banned users = 1 ('TestBanned')
        // Admin users = 2 ('Ivan', 'statsadmin')

        String adminToken = signInAndGetToken(admin.getUsername(), "adminpass");

        // When: Admin requests user stats
        mockMvc.perform(get("/api/v1/admin/users/stats")
                        .header("Authorization", "Bearer " + adminToken))
                // Then: Response is OK and stats are correct based on setup
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.totalUsers").value(4))
                .andExpect(jsonPath("$.activeUsers").value(3))
                .andExpect(jsonPath("$.bannedUsers").value(1))
                .andExpect(jsonPath("$.adminUsers").value(2));
    }

    @Test
    void givenNonAdminUser_whenGetUserStats_thenForbidden() throws Exception {
        // Given: A regular user signed in
        String regularUserToken = getUserAuthToken("statsnonadmin", "statsnonadmin@example.com", "userpass");

        // When: Regular user attempts to get stats
        mockMvc.perform(get("/api/v1/admin/users/stats")
                        .header("Authorization", "Bearer " + regularUserToken))
                // Then: Response is 403 Forbidden
                .andExpect(status().isForbidden());
    }

} 