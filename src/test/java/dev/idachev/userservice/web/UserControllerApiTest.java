package dev.idachev.userservice.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.idachev.userservice.config.ApiTestConfig;
import dev.idachev.userservice.model.Role;
import dev.idachev.userservice.service.TokenService;
import dev.idachev.userservice.service.UserService;
import dev.idachev.userservice.web.dto.GenericResponse;
import dev.idachev.userservice.web.dto.UserResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(UserController.class)
@Import(ApiTestConfig.class)
public class UserControllerApiTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockitoBean
    private UserService userService;

    @MockitoBean
    private TokenService tokenService;

    private UserResponse testUserResponse;
    private GenericResponse successResponse;
    private GenericResponse failureResponse;
    private UUID testUserId;

    @BeforeEach
    void setUp() {
        testUserId = UUID.randomUUID();

        // Set up test user response
        testUserResponse = UserResponse.builder()
                .id(testUserId)
                .username("testuser")
                .email("test@example.com")
                .role("USER")
                .verified(true)
                .verificationPending(false)
                .createdOn(LocalDateTime.now())
                .lastLogin(LocalDateTime.now())
                .build();

        // Set up success response
        successResponse = GenericResponse.builder()
                .status(200)
                .message("Operation successful")
                .timestamp(LocalDateTime.now())
                .success(true)
                .build();

        // Set up failure response
        failureResponse = GenericResponse.builder()
                .status(400)
                .message("Operation failed")
                .timestamp(LocalDateTime.now())
                .success(false)
                .build();
    }

    @Test
    public void checkUsernameAvailability_WhenUsernameIsAvailable_ReturnsTrue() throws Exception {
        // Given
        String username = "availableUsername";
        when(userService.existsByUsername(username)).thenReturn(false);

        GenericResponse expectedResponse = GenericResponse.builder()
                .status(200)
                .message("Username is available")
                .success(true)
                .build();

        // When
        ResultActions result = mockMvc.perform(get("/api/v1/user/check-username")
                .param("username", username)
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON));

        // Then
        result.andExpect(status().isOk())
                .andExpect(jsonPath("$.success", is(true)))
                .andExpect(jsonPath("$.message", is("Username is available")));

        verify(userService, times(1)).existsByUsername(username);
    }

    @Test
    public void checkUsernameAvailability_WhenUsernameIsTaken_ReturnsFalse() throws Exception {
        // Given
        String username = "takenUsername";
        when(userService.existsByUsername(username)).thenReturn(true);

        // When
        ResultActions result = mockMvc.perform(get("/api/v1/user/check-username")
                .param("username", username)
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON));

        // Then
        result.andExpect(status().isOk())
                .andExpect(jsonPath("$.success", is(false)))
                .andExpect(jsonPath("$.message", is("Username is already taken")));

        verify(userService, times(1)).existsByUsername(username);
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    public void getAllUsers_WhenAdmin_ReturnsAllUsers() throws Exception {
        // Given
        List<UserResponse> userResponses = Arrays.asList(
                testUserResponse,
                UserResponse.builder()
                        .id(UUID.randomUUID())
                        .username("anotheruser")
                        .email("another@example.com")
                        .role("USER")
                        .verified(true)
                        .build()
        );

        when(userService.getAllUsers()).thenReturn(userResponses);

        // When
        ResultActions result = mockMvc.perform(get("/api/v1/admin/users")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON));

        // Then
        result.andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(2)))
                .andExpect(jsonPath("$[0].username", is("testuser")))
                .andExpect(jsonPath("$[1].username", is("anotheruser")));

        verify(userService, times(1)).getAllUsers();
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    public void updateUserRole_WhenValidRequest_ReturnsSuccess() throws Exception {
        // Given
        when(userService.isCurrentUser(eq(testUserId))).thenReturn(false);
        when(userService.updateUserRoleWithTokenRefresh(eq(testUserId), eq(Role.ADMIN)))
                .thenReturn(successResponse);

        // When
        ResultActions result = mockMvc.perform(put("/api/v1/admin/users/{userId}/role", testUserId)
                .param("role", "ADMIN")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON));

        // Then
        result.andExpect(status().isOk())
                .andExpect(jsonPath("$.success", is(true)))
                .andExpect(jsonPath("$.message", is("Operation successful")));

        verify(userService, times(1)).updateUserRoleWithTokenRefresh(eq(testUserId), eq(Role.ADMIN));
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    public void updateUserRole_WhenUpdatingOwnRole_ReturnsBadRequest() throws Exception {
        // Given
        when(userService.isCurrentUser(eq(testUserId))).thenReturn(true);

        // When
        ResultActions result = mockMvc.perform(put("/api/v1/admin/users/{userId}/role", testUserId)
                .param("role", "USER")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON));

        // Then
        result.andExpect(status().isOk())
                .andExpect(jsonPath("$.success", is(false)))
                .andExpect(jsonPath("$.status", is(400)))
                .andExpect(jsonPath("$.message", is("Admins cannot change their own role")));

        verify(userService, never()).updateUserRoleWithTokenRefresh(any(), any());
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    public void toggleUserBan_WhenValidRequest_ReturnsSuccess() throws Exception {
        // Given
        GenericResponse banResponse = GenericResponse.builder()
                .status(200)
                .message("User has been banned")
                .timestamp(LocalDateTime.now())
                .success(true)
                .build();

        when(userService.isCurrentUser(eq(testUserId))).thenReturn(false);
        when(userService.toggleUserBan(eq(testUserId))).thenReturn(banResponse);

        // When
        ResultActions result = mockMvc.perform(put("/api/v1/admin/users/{userId}/ban", testUserId)
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON));

        // Then
        result.andExpect(status().isOk())
                .andExpect(jsonPath("$.success", is(true)))
                .andExpect(jsonPath("$.message", is("User has been banned")));

        verify(userService, times(1)).toggleUserBan(eq(testUserId));
        verify(tokenService, times(1)).invalidateUserTokens(eq(testUserId));
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    public void toggleUserBan_WhenBanningOwnAccount_ReturnsBadRequest() throws Exception {
        // Given
        when(userService.isCurrentUser(eq(testUserId))).thenReturn(true);

        // When
        ResultActions result = mockMvc.perform(put("/api/v1/admin/users/{userId}/ban", testUserId)
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON));

        // Then
        result.andExpect(status().isOk())
                .andExpect(jsonPath("$.success", is(false)))
                .andExpect(jsonPath("$.status", is(400)))
                .andExpect(jsonPath("$.message", is("Admins cannot ban themselves")));

        verify(userService, never()).toggleUserBan(any());
        verify(tokenService, never()).invalidateUserTokens(any());
    }

    @Test
    public void getAllUsers_WhenNotAdmin_ReturnsForbidden() throws Exception {
        // Given: User without admin role

        // When
        ResultActions result = mockMvc.perform(get("/api/v1/admin/users")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON));

        // Then
        result.andExpect(status().isForbidden());

        verify(userService, never()).getAllUsers();
    }
} 