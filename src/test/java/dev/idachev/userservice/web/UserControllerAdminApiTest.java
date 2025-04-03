package dev.idachev.userservice.web;

import dev.idachev.userservice.model.Role;
import dev.idachev.userservice.service.UserService;
import dev.idachev.userservice.web.dto.GenericResponse;
import dev.idachev.userservice.web.dto.UserResponse;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@WithMockUser(roles = "ADMIN") // Default to ADMIN for all tests in this class
public class UserControllerAdminApiTest {

    @MockitoBean
    private UserService userService;

    @Autowired
    private MockMvc mockMvc;

    @Test
    void getAllUsers_Admin_ReturnsAllUsers() throws Exception {
        // Given
        UserResponse user1 = UserResponse.builder()
                .id(UUID.randomUUID())
                .username("user1")
                .email("user1@example.com")
                .role(Role.USER.name())
                .build();

        UserResponse user2 = UserResponse.builder()
                .id(UUID.randomUUID())
                .username("user2")
                .email("user2@example.com")
                .role(Role.ADMIN.name())
                .build();

        List<UserResponse> users = Arrays.asList(user1, user2);
        when(userService.getAllUsers()).thenReturn(users);

        // When
        MockHttpServletRequestBuilder request = get("/api/v1/admin/users")
                .with(csrf());

        // Then
        mockMvc.perform(request)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].username").value("user1"))
                .andExpect(jsonPath("$[1].username").value("user2"));
    }

    @Test
    @WithMockUser(roles = "USER")
        // Override for specific non-admin test
    void getAllUsers_NonAdmin_ReturnsForbidden() throws Exception {
        // Given - non-admin user
        // When
        MockHttpServletRequestBuilder request = get("/api/v1/admin/users")
                .with(csrf());

        // Then
        mockMvc.perform(request)
                .andExpect(status().isForbidden());
    }

    @Test
    void updateUserRole_Admin_ReturnsSuccess() throws Exception {
        // Given
        UUID userId = UUID.randomUUID();
        Role newRole = Role.ADMIN;

        GenericResponse response = GenericResponse.builder()
                .status(200)
                .message("User role updated successfully")
                .build();

        when(userService.setUserRole(eq(userId), eq(newRole))).thenReturn(response);

        // When
        MockHttpServletRequestBuilder request = put("/api/v1/admin/users/{userId}/role", userId)
                .with(csrf())
                .param("role", newRole.name());

        // Then
        mockMvc.perform(request)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value(200))
                .andExpect(jsonPath("$.message").value("User role updated successfully"));
    }

    @Test
    @WithMockUser(roles = "USER")
        // Override for specific non-admin test
    void updateUserRole_NonAdmin_ReturnsForbidden() throws Exception {
        // Given - non-admin user
        UUID userId = UUID.randomUUID();
        Role newRole = Role.ADMIN;

        // When
        MockHttpServletRequestBuilder request = put("/api/v1/admin/users/{userId}/role", userId)
                .with(csrf())
                .param("role", newRole.name());

        // Then
        mockMvc.perform(request)
                .andExpect(status().isForbidden());
    }

    @Test
    void toggleUserBan_Admin_ReturnsSuccess() throws Exception {
        // Given
        UUID userId = UUID.randomUUID();
        GenericResponse response = GenericResponse.builder()
                .status(200)
                .message("User ban status toggled successfully")
                .build();

        when(userService.toggleUserBan(eq(userId))).thenReturn(response);

        // When
        MockHttpServletRequestBuilder request = put("/api/v1/admin/users/{userId}/ban", userId)
                .with(csrf());

        // Then
        mockMvc.perform(request)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("User ban status toggled successfully"));
    }

    @Test
    @WithMockUser(roles = "USER")
        // Override for specific non-admin test
    void toggleUserBan_NonAdmin_ReturnsForbidden() throws Exception {
        // Given - non-admin user
        UUID userId = UUID.randomUUID();

        // When
        MockHttpServletRequestBuilder request = put("/api/v1/admin/users/{userId}/ban", userId)
                .with(csrf());

        // Then
        mockMvc.perform(request)
                .andExpect(status().isForbidden());
    }
} 