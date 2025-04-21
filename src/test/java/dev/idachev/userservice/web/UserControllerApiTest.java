package dev.idachev.userservice.web;

import dev.idachev.userservice.config.JwtConfig;
import dev.idachev.userservice.model.Role;
import dev.idachev.userservice.model.User;
import dev.idachev.userservice.service.TokenBlacklistService;
import dev.idachev.userservice.service.UserDetailsService;
import dev.idachev.userservice.service.UserService;
import dev.idachev.userservice.web.dto.UserResponse;
import dev.idachev.userservice.web.dto.UserStatsResponse;
import dev.idachev.userservice.web.dto.UsernameAvailabilityResponse;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.then;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(UserController.class)
@DisplayName("UserController Tests")
class UserControllerApiTest {

    @Autowired
    private MockMvc mockMvc;
    @MockitoBean
    private UserService userService;
    @MockitoBean
    private JwtConfig jwtConfig;
    @MockitoBean
    private UserDetailsService userDetailsService;
    @MockitoBean
    private TokenBlacklistService tokenBlacklistService;

    // Potential need for TestSecurityConfig for @PreAuthorize noted implicitly by usage.

    @Test
    @DisplayName("GET /users/check-username - Success (Available)")
    @WithMockUser
    void checkUsernameAvailability_Available() throws Exception {
        String username = "availableUsername";
        UsernameAvailabilityResponse mockResponse = UsernameAvailabilityResponse.builder()
                .username(username).available(true).message("Username is available").build();

        given(userService.checkUsernameAvailability(username)).willReturn(mockResponse);

        mockMvc.perform(get("/api/v1/users/check-username")
                        .param("username", username))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.username").value(username))
                .andExpect(jsonPath("$.available").value(true));

        then(userService).should().checkUsernameAvailability(username);
    }

    @Test
    @DisplayName("GET /users/check-username - Success (Not Available)")
    @WithMockUser
    void checkUsernameAvailability_NotAvailable() throws Exception {
        String username = "takenUsername";
        UsernameAvailabilityResponse mockResponse = UsernameAvailabilityResponse.builder()
                .username(username).available(false).message("Username is already taken").build();

        given(userService.checkUsernameAvailability(username)).willReturn(mockResponse);

        mockMvc.perform(get("/api/v1/users/check-username")
                        .param("username", username))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.username").value(username))
                .andExpect(jsonPath("$.available").value(false));

        then(userService).should().checkUsernameAvailability(username);
    }

    @Test
    @DisplayName("PUT /admin/users/{userId}/role - Success (Admin)")
    @WithMockUser(roles = "ADMIN")
    void updateUserRoleAdmin_Success() throws Exception {
        UUID userId = UUID.randomUUID();
        Role newRole = Role.ADMIN;
        User mockUpdatedUser = User.builder()
                .id(userId).username("userToUpdate").role(newRole).build();

        given(userService.updateUserRole(userId, newRole)).willReturn(mockUpdatedUser);

        mockMvc.perform(put("/api/v1/admin/users/{userId}/role", userId)
                        .with(csrf())
                        .param("role", newRole.name()))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.userId").value(userId.toString()))
                .andExpect(jsonPath("$.role").value(newRole.name()))
                .andExpect(jsonPath("$.tokenRefreshed").value(true));

        then(userService).should().updateUserRole(userId, newRole);
    }

    @Test
    @DisplayName("PUT /admin/users/{userId}/ban - Success (Ban User)")
    @WithMockUser(roles = "ADMIN")
    void toggleUserBanAdmin_BanSuccess() throws Exception {
        UUID userId = UUID.randomUUID();
        User mockUpdatedUser = User.builder()
                .id(userId).username("userToBan").banned(true).build();

        given(userService.toggleUserBan(userId)).willReturn(mockUpdatedUser);

        mockMvc.perform(put("/api/v1/admin/users/{userId}/ban", userId)
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.userId").value(userId.toString()))
                .andExpect(jsonPath("$.banned").value(true))
                .andExpect(jsonPath("$.message").value("User banned successfully"));

        then(userService).should().toggleUserBan(userId);
    }

    @Test
    @DisplayName("PUT /admin/users/{userId}/ban - Success (Unban User)")
    @WithMockUser(roles = "ADMIN")
    void toggleUserBanAdmin_UnbanSuccess() throws Exception {
        UUID userId = UUID.randomUUID();
        User mockUpdatedUser = User.builder()
                .id(userId).username("userToUnban").banned(false).build();

        given(userService.toggleUserBan(userId)).willReturn(mockUpdatedUser);

        mockMvc.perform(put("/api/v1/admin/users/{userId}/ban", userId)
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.userId").value(userId.toString()))
                .andExpect(jsonPath("$.banned").value(false))
                .andExpect(jsonPath("$.message").value("User unbanned successfully"));

        then(userService).should().toggleUserBan(userId);
    }

    @Test
    @DisplayName("GET /admin/users/{userId} - Success (Admin)")
    @WithMockUser(roles = "ADMIN")
    void getUserByIdAdmin_Success() throws Exception {
        UUID userId = UUID.randomUUID();
        UserResponse mockUserResponse = UserResponse.builder()
                .id(userId).username("specificUser").email("specific@example.com").role("USER").build();

        given(userService.getUserById(userId)).willReturn(mockUserResponse);

        mockMvc.perform(get("/api/v1/admin/users/{userId}", userId))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.id").value(userId.toString()))
                .andExpect(jsonPath("$.username").value("specificUser"));

        then(userService).should().getUserById(userId);
    }

    @Test
    @DisplayName("DELETE /admin/users/{userId} - Success (Admin)")
    @WithMockUser(roles = "ADMIN")
    void deleteUserAdmin_Success() throws Exception {
        UUID userId = UUID.randomUUID();

        mockMvc.perform(delete("/api/v1/admin/users/{userId}", userId)
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.message").value("User successfully deleted"));

        then(userService).should().deleteUser(userId);
    }

    @Test
    @DisplayName("GET /admin/users/stats - Success (Admin)")
    @WithMockUser(roles = "ADMIN")
    void getUserStatsAdmin_Success() throws Exception {
        UserStatsResponse mockStats = UserStatsResponse.builder()
                .totalUsers(100L).activeUsers(95L).verifiedUsers(80L)
                .bannedUsers(5L).adminUsers(10L).timestamp(LocalDateTime.now()).build();

        given(userService.getUserStats()).willReturn(mockStats);

        mockMvc.perform(get("/api/v1/admin/users/stats"))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.totalUsers").value(100))
                .andExpect(jsonPath("$.activeUsers").value(95))
                .andExpect(jsonPath("$.verifiedUsers").value(80))
                .andExpect(jsonPath("$.bannedUsers").value(5))
                .andExpect(jsonPath("$.adminUsers").value(10))
                .andExpect(jsonPath("$.timestamp").exists());

        then(userService).should().getUserStats();
    }

    @Test
    @DisplayName("GET /admin/users - Success (Admin)")
    @WithMockUser(roles = "ADMIN")
    void getAllUsersAdmin_Success() throws Exception {
        UserResponse user1 = UserResponse.builder().id(UUID.randomUUID()).username("user1").email("user1@example.com").role("USER").build();
        UserResponse user2 = UserResponse.builder().id(UUID.randomUUID()).username("user2").email("user2@example.com").role("ADMIN").build();
        List<UserResponse> mockUserList = Arrays.asList(user1, user2);

        given(userService.getAllUsers()).willReturn(mockUserList);

        mockMvc.perform(get("/api/v1/admin/users"))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.size()").value(2))
                .andExpect(jsonPath("$[0].username").value("user1"))
                .andExpect(jsonPath("$[1].username").value("user2"));

        then(userService).should().getAllUsers();
    }
} 