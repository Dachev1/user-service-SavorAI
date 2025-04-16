package dev.idachev.userservice.web;

import dev.idachev.userservice.model.Role;
import dev.idachev.userservice.service.AuthenticationService;
import dev.idachev.userservice.service.ProfileService;
import dev.idachev.userservice.service.UserService;
import dev.idachev.userservice.web.dto.BanStatusResponse;
import dev.idachev.userservice.web.dto.GenericResponse;
import dev.idachev.userservice.web.dto.ProfileUpdateRequest;
import dev.idachev.userservice.web.dto.RoleUpdateResponse;
import dev.idachev.userservice.web.dto.UserResponse;
import dev.idachev.userservice.web.dto.UsernameAvailabilityResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class UserControllerApiTest {

    @Mock
    private UserService userService;

    @Mock
    private AuthenticationService authenticationService;

    @Mock
    private ProfileService profileService;

    @InjectMocks
    private UserController userController;

    private UUID userId;
    private UserResponse userResponse;
    private String username;

    @BeforeEach
    void setUp() {
        userId = UUID.randomUUID();
        username = "testuser";
        userResponse = UserResponse.builder()
                .id(userId)
                .username(username)
                .email("test@example.com")
                .role("USER")
                .verified(true)
                .createdOn(LocalDateTime.now())
                .build();
    }

    @Test
    @DisplayName("Should check username availability")
    void should_CheckUsernameAvailability() {
        // Given
        String username = "newuser";
        UsernameAvailabilityResponse expectedResponse = UsernameAvailabilityResponse.of(username, true);
        
        when(userService.checkUsernameAvailability(username)).thenReturn(expectedResponse);

        // When
        ResponseEntity<UsernameAvailabilityResponse> response = userController.checkUsernameAvailability(username);

        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isEqualTo(expectedResponse);
        verify(userService).checkUsernameAvailability(username);
    }

    @Test
    @DisplayName("Should get current user information when authenticated")
    void should_GetCurrentUserInfo_WhenAuthenticated() {
        // Given
        when(profileService.getCurrentUserInfo()).thenReturn(userResponse);

        // When
        ResponseEntity<UserResponse> response = userController.getCurrentUser();

        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isEqualTo(userResponse);
        verify(profileService).getCurrentUserInfo();
    }

    @Test
    @DisplayName("Should get all users when requested by admin")
    void should_GetAllUsers_WhenRequestedByAdmin() {
        // Given
        List<UserResponse> expectedUsers = Arrays.asList(
                userResponse,
                UserResponse.builder()
                        .id(UUID.randomUUID())
                        .username("user2")
                        .email("user2@example.com")
                        .role("USER")
                        .verified(true)
                        .createdOn(LocalDateTime.now())
                        .build()
        );
        when(userService.getAllUsers()).thenReturn(expectedUsers);

        // When
        ResponseEntity<List<UserResponse>> response = userController.getAllUsers();

        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isEqualTo(expectedUsers);
        assertThat(response.getBody().size()).isEqualTo(2);
        verify(userService).getAllUsers();
    }

    @Test
    @DisplayName("Should get user by id when user exists")
    void should_GetUserById_WhenUserExists() {
        // Given
        when(userService.getUserById(userId)).thenReturn(userResponse);

        // When
        ResponseEntity<UserResponse> response = userController.getUserById(userId);

        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isEqualTo(userResponse);
        verify(userService).getUserById(userId);
    }

    @Test
    @DisplayName("Should get username by id when user exists")
    void should_GetUsernameById_WhenUserExists() {
        // Given
        when(userService.getUsernameById(userId)).thenReturn(username);

        // When
        ResponseEntity<String> response = userController.getUsernameById(userId);

        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isEqualTo(username);
        verify(userService).getUsernameById(userId);
    }

    @Test
    @DisplayName("Should update user role when admin requests")
    void should_UpdateUserRole_WhenAdminRequests() {
        // Given
        Role newRole = Role.ADMIN;
        RoleUpdateResponse expectedResponse = RoleUpdateResponse.builder()
                .userId(userId)
                .success(true)
                .message("Role updated successfully")
                .build();

        when(userService.updateUserRole(userId, newRole)).thenReturn(expectedResponse);

        // When
        ResponseEntity<RoleUpdateResponse> response = userController.updateUserRole(userId, newRole);

        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isEqualTo(expectedResponse);
        verify(userService).updateUserRole(userId, newRole);
    }

    @Test
    @DisplayName("Should toggle user ban status when admin requests")
    void should_ToggleUserBan_WhenAdminRequests() {
        // Given
        BanStatusResponse expectedResponse = BanStatusResponse.builder()
                .userId(userId)
                .success(true)
                .banned(true)
                .message("User banned successfully")
                .build();

        when(userService.toggleUserBan(userId)).thenReturn(expectedResponse);

        // When
        ResponseEntity<BanStatusResponse> response = userController.toggleUserBan(userId);

        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isEqualTo(expectedResponse);
        verify(userService).toggleUserBan(userId);
    }
} 