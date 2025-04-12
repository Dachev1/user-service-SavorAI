package dev.idachev.userservice.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.idachev.userservice.config.TestSecurityConfig;
import dev.idachev.userservice.exception.UserNotFoundException;
import dev.idachev.userservice.model.Role;
import dev.idachev.userservice.service.TokenService;
import dev.idachev.userservice.service.UserService;
import dev.idachev.userservice.web.dto.GenericResponse;
import dev.idachev.userservice.web.dto.UserResponse;
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
import java.util.List;
import java.util.UUID;

import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(controllers = UserController.class)
@AutoConfigureMockMvc(addFilters = false)
@Import(TestSecurityConfig.class)
public class UserControllerApiTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockitoBean
    private UserService userService;

    @MockitoBean
    private TokenService tokenService;

    private UserResponse userResponse;
    private GenericResponse successResponse;
    private UUID userId;

    @BeforeEach
    void setUp() {
        userId = UUID.randomUUID();

        userResponse = UserResponse.builder()
                .id(userId)
                .username("testuser")
                .email("test@example.com")
                .verified(true)
                .verificationPending(false)
                .banned(false)
                .role("USER")
                .createdOn(LocalDateTime.now())
                .lastLogin(LocalDateTime.now())
                .build();

        successResponse = GenericResponse.builder()
                .status(200)
                .message("Operation successful")
                .timestamp(LocalDateTime.now())
                .success(true)
                .build();
    }

    @Test
    public void checkUsernameAvailability_WhenUsernameAvailable_ReturnsSuccess() throws Exception {
        String username = "availableuser";
        when(userService.checkUsernameAvailability(username)).thenReturn(
            GenericResponse.builder()
                .status(200)
                .message("Username is available")
                .timestamp(LocalDateTime.now())
                .success(true)
                .build()
        );

        mockMvc.perform(get("/api/v1/user/check-username")
                        .param("username", username)
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success", is(true)))
                .andExpect(jsonPath("$.message", is("Username is available")));

        verify(userService).checkUsernameAvailability(username);
    }

    @Test
    public void checkUsernameAvailability_WhenUsernameTaken_ReturnsFailure() throws Exception {
        String username = "takenuser";
        when(userService.checkUsernameAvailability(username)).thenReturn(
            GenericResponse.builder()
                .status(200)
                .message("Username is already taken")
                .timestamp(LocalDateTime.now())
                .success(false)
                .build()
        );

        mockMvc.perform(get("/api/v1/user/check-username")
                        .param("username", username)
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success", is(false)))
                .andExpect(jsonPath("$.message", is("Username is already taken")));

        verify(userService).checkUsernameAvailability(username);
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    public void getAllUsers_WhenAdmin_ReturnsUsers() throws Exception {
        when(userService.getAllUsers()).thenReturn(List.of(userResponse));

        mockMvc.perform(get("/api/v1/admin/users")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].username", is("testuser")))
                .andExpect(jsonPath("$[0].email", is("test@example.com")))
                .andExpect(jsonPath("$[0].role", is("USER")));

        verify(userService).getAllUsers();
    }

    @Test
    @WithMockUser(username = "admin", roles = "ADMIN")
    public void updateUserRole_WhenValidRequest_ReturnsSuccess() throws Exception {
        when(userService.isCurrentUser(userId)).thenReturn(false);
        when(userService.updateUserRoleWithTokenRefresh(userId, Role.ADMIN)).thenReturn(successResponse);

        mockMvc.perform(put("/api/v1/admin/users/{userId}/role", userId)
                        .param("role", "ADMIN")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success", is(true)));

        verify(userService).updateUserRoleWithTokenRefresh(userId, Role.ADMIN);
    }

    @Test
    @WithMockUser(username = "admin", roles = "ADMIN")
    public void updateUserRole_WhenUserNotFound_ReturnsNotFound() throws Exception {
        when(userService.isCurrentUser(userId)).thenReturn(false);
        when(userService.updateUserRoleWithTokenRefresh(userId, Role.ADMIN))
                .thenThrow(new UserNotFoundException("User not found"));

        mockMvc.perform(put("/api/v1/admin/users/{userId}/role", userId)
                        .param("role", "ADMIN")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isNotFound());

        verify(userService).updateUserRoleWithTokenRefresh(userId, Role.ADMIN);
    }

    @Test
    @WithMockUser(username = "admin", roles = "ADMIN")
    public void updateUserRole_WhenUpdatingOwnRole_ReturnsBadRequest() throws Exception {
        when(userService.isCurrentUser(userId)).thenReturn(true);

        mockMvc.perform(put("/api/v1/admin/users/{userId}/role", userId)
                        .param("role", "USER")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.success", is(false)))
                .andExpect(jsonPath("$.message", is("Admins cannot change their own role")));

        verify(userService, never()).updateUserRoleWithTokenRefresh(any(), any());
    }

    @Test
    @WithMockUser(username = "admin", roles = "ADMIN")
    public void toggleUserBan_WhenValidRequest_ReturnsSuccess() throws Exception {
        when(userService.isCurrentUser(userId)).thenReturn(false);
        when(userService.toggleUserBan(userId)).thenReturn(successResponse);

        mockMvc.perform(put("/api/v1/admin/users/{userId}/ban", userId)
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success", is(true)));

        verify(userService).toggleUserBan(userId);
    }

    @Test
    @WithMockUser(username = "admin", roles = "ADMIN")
    public void toggleUserBan_WhenUserNotFound_ReturnsNotFound() throws Exception {
        when(userService.isCurrentUser(userId)).thenReturn(false);
        when(userService.toggleUserBan(userId))
                .thenThrow(new UserNotFoundException("User not found"));

        mockMvc.perform(put("/api/v1/admin/users/{userId}/ban", userId)
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isNotFound());

        verify(userService).toggleUserBan(userId);
    }

    @Test
    @WithMockUser(username = "admin", roles = "ADMIN")
    public void toggleUserBan_WhenBanningSelf_ReturnsBadRequest() throws Exception {
        when(userService.isCurrentUser(userId)).thenReturn(true);

        mockMvc.perform(put("/api/v1/admin/users/{userId}/ban", userId)
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.success", is(false)))
                .andExpect(jsonPath("$.message", is("Admins cannot ban themselves")));

        verify(userService, never()).toggleUserBan(any());
    }

    @Test
    @WithMockUser(username = "admin", roles = "ADMIN")
    public void toggleUserBan_WhenUserBanned_InvalidatesTokens() throws Exception {
        when(userService.isCurrentUser(userId)).thenReturn(false);
        GenericResponse banResponse = GenericResponse.builder()
                .status(200)
                .message("User has been banned")
                .timestamp(LocalDateTime.now())
                .success(true)
                .build();

        when(userService.toggleUserBan(userId)).thenReturn(banResponse);

        mockMvc.perform(put("/api/v1/admin/users/{userId}/ban", userId)
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk());

        verify(userService).toggleUserBan(userId);
        verify(tokenService).invalidateUserTokens(userId);
    }
} 