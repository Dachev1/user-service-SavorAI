package dev.idachev.userservice.service;

import dev.idachev.userservice.exception.AuthenticationException;
import dev.idachev.userservice.exception.InvalidRequestException;
import dev.idachev.userservice.exception.ResourceNotFoundException;
import dev.idachev.userservice.model.Role;
import dev.idachev.userservice.model.User;
import dev.idachev.userservice.repository.UserRepository;
import dev.idachev.userservice.security.UserPrincipal;
import dev.idachev.userservice.web.dto.PasswordChangeRequest;
import dev.idachev.userservice.web.dto.ProfileUpdateRequest;
import dev.idachev.userservice.web.dto.UserResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class ProfileServiceUTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private UserDetailsService userDetailsService;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private SecurityContext securityContext;

    @Mock
    private Authentication authentication;

    @Captor
    private ArgumentCaptor<User> userCaptor;

    private ProfileService profileService;

    private UUID userId;
    private User testUser;

    @BeforeEach
    void setUp() {
        profileService = new ProfileService(userRepository, userDetailsService, passwordEncoder);

        userId = UUID.randomUUID();
        testUser = User.builder()
                .id(userId)
                .username("testuser")
                .email("test@example.com")
                .password("encodedPassword")
                .role(Role.USER)
                .enabled(true)
                .createdOn(LocalDateTime.now())
                .updatedOn(LocalDateTime.now())
                .build();

        SecurityContextHolder.setContext(securityContext);
    }

    @Test
    @DisplayName("Should get current user when user is authenticated")
    void should_GetCurrentUser_When_UserIsAuthenticated() {
        // Given
        UserPrincipal userPrincipal = new UserPrincipal(testUser);

        when(securityContext.getAuthentication()).thenReturn(authentication);
        when(authentication.isAuthenticated()).thenReturn(true);
        when(authentication.getPrincipal()).thenReturn(userPrincipal);

        // When
        User result = profileService.getCurrentUser();

        // Then
        assertThat(result).isNotNull();
        assertThat(result.getId()).isEqualTo(userId);
        assertThat(result.getUsername()).isEqualTo(testUser.getUsername());
    }

    @Test
    @DisplayName("Should throw AuthenticationException when user is not authenticated")
    void should_ThrowAuthenticationException_When_UserIsNotAuthenticated() {
        // Given
        when(securityContext.getAuthentication()).thenReturn(authentication);
        when(authentication.isAuthenticated()).thenReturn(false);

        // When/Then
        assertThatThrownBy(() -> profileService.getCurrentUser())
                .isInstanceOf(AuthenticationException.class)
                .hasMessageContaining("User not authenticated");
    }

    @Test
    @DisplayName("Should get current user information when user is authenticated")
    void should_GetCurrentUserInfo_When_UserIsAuthenticated() {
        // Given
        UserPrincipal userPrincipal = new UserPrincipal(testUser);

        when(securityContext.getAuthentication()).thenReturn(authentication);
        when(authentication.isAuthenticated()).thenReturn(true);
        when(authentication.getPrincipal()).thenReturn(userPrincipal);

        // When
        UserResponse result = profileService.getCurrentUserInfo();

        // Then
        assertThat(result).isNotNull();
        assertThat(result.getId()).isEqualTo(userId);
        assertThat(result.getUsername()).isEqualTo(testUser.getUsername());
    }

    @Test
    @DisplayName("Should get user info by identifier when user exists")
    void should_GetUserInfo_When_UserExists() {
        // Given
        String username = "testuser";

        when(userRepository.findByUsername(username)).thenReturn(Optional.of(testUser));

        // When
        UserResponse result = profileService.getUserInfo(username);

        // Then
        assertThat(result).isNotNull();
        assertThat(result.getId()).isEqualTo(userId);
        assertThat(result.getUsername()).isEqualTo(username);
    }

    @Test
    @DisplayName("Should throw ResourceNotFoundException when user does not exist")
    void should_ThrowResourceNotFoundException_When_UserDoesNotExist() {
        // Given
        String nonExistingUsername = "nonexistinguser";

        when(userRepository.findByUsername(nonExistingUsername)).thenReturn(Optional.empty());

        // When/Then
        assertThatThrownBy(() -> profileService.getUserInfo(nonExistingUsername))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessageContaining("User not found");
    }

    @Test
    @DisplayName("Should update username when valid request is provided")
    void should_UpdateUsername_When_ValidRequestIsProvided() {
        // Given
        String currentUsername = "testuser";
        String newUsername = "newusername";
        ProfileUpdateRequest request = new ProfileUpdateRequest();
        request.setUsername(newUsername);

        when(userRepository.findByUsername(currentUsername)).thenReturn(Optional.of(testUser));
        when(userRepository.existsByUsername(newUsername)).thenReturn(false);
        when(userRepository.save(any(User.class))).thenReturn(testUser);

        // When
        UserResponse result = profileService.updateProfile(currentUsername, request);

        // Then
        verify(userRepository).save(userCaptor.capture());
        User savedUser = userCaptor.getValue();
        verify(userDetailsService).handleUsernameChange(eq(currentUsername), eq(newUsername), any(UUID.class));

        assertThat(result).isNotNull();
        assertThat(savedUser.getUsername()).isEqualTo(newUsername);
    }

    @Test
    @DisplayName("Should throw IllegalArgumentException when updating with taken username")
    void should_ThrowIllegalArgumentException_When_UpdatingWithTakenUsername() {
        // Given
        String currentUsername = "testuser";
        String takenUsername = "takenusername";
        ProfileUpdateRequest request = new ProfileUpdateRequest();
        request.setUsername(takenUsername);

        when(userRepository.findByUsername(currentUsername)).thenReturn(Optional.of(testUser));
        when(userRepository.existsByUsername(takenUsername)).thenReturn(true);

        // When/Then
        assertThatThrownBy(() -> profileService.updateProfile(currentUsername, request))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Username is already taken");
    }

    @Test
    @DisplayName("Should delete user account when user exists")
    void should_DeleteAccount_When_UserExists() {
        // Given
        String username = "testuser";
        when(userRepository.findByUsername(username)).thenReturn(Optional.of(testUser));
        
        // When
        profileService.deleteAccount(username);
        
        // Then
        verify(userRepository).delete(testUser);
    }
    
    @Test
    @DisplayName("Should throw ResourceNotFoundException when deleting non-existent user")
    void should_ThrowResourceNotFoundException_When_DeletingNonExistentUser() {
        // Given
        String nonExistingUsername = "nonexistinguser";
        when(userRepository.findByUsername(nonExistingUsername)).thenReturn(Optional.empty());
        
        // When/Then
        assertThatThrownBy(() -> profileService.deleteAccount(nonExistingUsername))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessageContaining("User not found");
    }
    
    @Test
    @DisplayName("Should change password when valid request is provided")
    void should_ChangePassword_When_ValidRequestIsProvided() {
        // Given
        String username = "testuser";
        String currentPassword = "password123";
        String newPassword = "newPassword123";
        String encodedNewPassword = "encodedNewPassword123";
        
        PasswordChangeRequest request = PasswordChangeRequest.builder()
                .currentPassword(currentPassword)
                .newPassword(newPassword)
                .confirmPassword(newPassword)
                .build();
        
        when(userRepository.findByUsername(username)).thenReturn(Optional.of(testUser));
        when(passwordEncoder.matches(currentPassword, testUser.getPassword())).thenReturn(true);
        when(passwordEncoder.encode(newPassword)).thenReturn(encodedNewPassword);
        
        // When
        profileService.changePassword(username, request);
        
        // Then
        verify(userRepository).save(userCaptor.capture());
        User savedUser = userCaptor.getValue();
        
        assertThat(savedUser.getPassword()).isEqualTo(encodedNewPassword);
    }
    
    @Test
    @DisplayName("Should throw InvalidRequestException when current password is incorrect")
    void should_ThrowInvalidRequestException_When_CurrentPasswordIsIncorrect() {
        // Given
        String username = "testuser";
        String wrongCurrentPassword = "wrongPassword";
        String newPassword = "newPassword123";
        
        PasswordChangeRequest request = PasswordChangeRequest.builder()
                .currentPassword(wrongCurrentPassword)
                .newPassword(newPassword)
                .confirmPassword(newPassword)
                .build();
        
        when(userRepository.findByUsername(username)).thenReturn(Optional.of(testUser));
        when(passwordEncoder.matches(wrongCurrentPassword, testUser.getPassword())).thenReturn(false);
        
        // When/Then
        assertThatThrownBy(() -> profileService.changePassword(username, request))
                .isInstanceOf(InvalidRequestException.class)
                .hasMessageContaining("Current password is incorrect");
    }
    
    @Test
    @DisplayName("Should throw InvalidRequestException when passwords don't match")
    void should_ThrowInvalidRequestException_When_PasswordsDontMatch() {
        // Given
        String username = "testuser";
        String currentPassword = "password123";
        String newPassword = "newPassword123";
        String confirmPassword = "differentPassword123";
        
        PasswordChangeRequest request = PasswordChangeRequest.builder()
                .currentPassword(currentPassword)
                .newPassword(newPassword)
                .confirmPassword(confirmPassword)
                .build();
        
        when(userRepository.findByUsername(username)).thenReturn(Optional.of(testUser));
        when(passwordEncoder.matches(currentPassword, testUser.getPassword())).thenReturn(true);
        
        // When/Then
        assertThatThrownBy(() -> profileService.changePassword(username, request))
                .isInstanceOf(InvalidRequestException.class)
                .hasMessageContaining("New password and confirmation do not match");
    }
} 