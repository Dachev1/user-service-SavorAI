package dev.idachev.userservice.web;

import dev.idachev.userservice.config.JwtConfig;
import dev.idachev.userservice.config.SecurityConfig;
import dev.idachev.userservice.service.TokenBlacklistService;
import dev.idachev.userservice.service.UserService;
import dev.idachev.userservice.web.dto.GenericResponse;
import dev.idachev.userservice.web.dto.UserResponse;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(AdminController.class)
@Import(SecurityConfig.class)
public class AdminControllerApiTest {

    @MockitoBean
    private UserService userService;

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

    @Test
    @WithMockUser(roles = "ADMIN")
    void getAllUsers_ReturnsUsersList() throws Exception {

        // Given
        List<UserResponse> users = Arrays.asList(
                UserResponse.builder().id(UUID.randomUUID()).email("user1@example.com").build(),
                UserResponse.builder().id(UUID.randomUUID()).email("user2@example.com").build()
        );
        when(userService.getAllUsers()).thenReturn(users);

        // When
        MockHttpServletRequestBuilder request = get("/api/v1/admin/users");

        // Then
        mockMvc.perform(request)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].id").exists())
                .andExpect(jsonPath("$[0].email").value("user1@example.com"))
                .andExpect(jsonPath("$[1].email").value("user2@example.com"));
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    void setUserRole_ReturnsSuccess() throws Exception {

        // Given
        UUID userId = UUID.randomUUID();
        GenericResponse response = GenericResponse.builder()
                .message("Role updated successfully")
                .build();
        when(userService.setUserRole(any(), any())).thenReturn(response);

        // When
        MockHttpServletRequestBuilder request = put("/api/v1/admin/users/{userId}/role", userId)
                .param("role", "USER");

        // Then
        mockMvc.perform(request)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Role updated successfully"));
    }

    @Test
    @WithMockUser(roles = "USER")
    void getAllUsers_WithUserRole_ReturnsForbidden() throws Exception {

        // Given
        MockHttpServletRequestBuilder request = get("/api/v1/admin/users");

        // When & Then
        mockMvc.perform(request)
                .andExpect(status().isForbidden());
    }
} 