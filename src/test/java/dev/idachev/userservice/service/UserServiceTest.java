package dev.idachev.userservice.service;

import dev.idachev.userservice.exception.ResourceNotFoundException;
import dev.idachev.userservice.mapper.DtoMapper;
import dev.idachev.userservice.mapper.EntityMapper;
import dev.idachev.userservice.model.Role;
import dev.idachev.userservice.model.User;
import dev.idachev.userservice.repository.UserRepository;
import dev.idachev.userservice.security.UserPrincipal;
import dev.idachev.userservice.web.dto.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.cache.CacheManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class UserServiceUTest {

    @Mock
    private UserRepository userRepository;
    
    @Mock
    private UserDetailsService userDetailsService;
    
    @Mock
    private CacheManager cacheManager;
    
    @Mock
    private PasswordEncoder passwordEncoder;
    
    @Mock
    private EmailService emailService;
    
    @Mock
    private TokenService tokenService;
    
    @Mock
    private SecurityContext securityContext;
    
    @Mock
    private Authentication authentication;
    
    @Captor
    private ArgumentCaptor<User> userCaptor;
    
    private UserService userService;
    
    private UUID userId;
    private User testUser;
    
    @BeforeEach
    void setUp() {
        userService = new UserService(
            userRepository,
            userDetailsService,
            cacheManager,
            passwordEncoder,
            emailService,
            tokenService
        );
        
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
    }
    
    @Test
    @DisplayName("Should successfully register new user when valid request is provided")
    void should_RegisterNewUser_When_ValidRequestIsProvided() {
        // Given
        RegisterRequest request = new RegisterRequest(
                "newuser", 
                "new@example.com", 
                "Password123"
        );
        String verificationToken = "verification-token";
        User newUser = User.builder()
                .username(request.getUsername())
                .email(request.getEmail())
                .password("encodedPassword")
                .verificationToken(verificationToken)
                .build();
        
        when(emailService.generateVerificationToken()).thenReturn(verificationToken);
        when(userRepository.save(any(User.class))).thenReturn(newUser);
        
        // When
        User result = userService.registerUser(request);
        
        // Then
        verify(userRepository).save(userCaptor.capture());
        User capturedUser = userCaptor.getValue();
        
        assertThat(result).isNotNull();
        assertThat(capturedUser.getUsername()).isEqualTo(request.getUsername());
        assertThat(capturedUser.getEmail()).isEqualTo(request.getEmail());
        assertThat(capturedUser.getVerificationToken()).isEqualTo(verificationToken);
    }
    
    @Test
    @DisplayName("Should return all users when requested")
    void should_ReturnAllUsers_When_Requested() {
        // Given
        List<User> users = List.of(
                testUser,
                User.builder()
                    .id(UUID.randomUUID())
                    .username("user2")
                    .email("user2@example.com")
                    .password("encoded")
                    .role(Role.USER)
                    .enabled(true)
                    .build()
        );
        
        when(userRepository.findAll()).thenReturn(users);
        
        // When
        List<UserResponse> result = userService.getAllUsers();
        
        // Then
        assertThat(result).hasSize(2);
        assertThat(result.get(0).getUsername()).isEqualTo("testuser");
        assertThat(result.get(1).getUsername()).isEqualTo("user2");
    }
    
    @Test
    @DisplayName("Should update user role when valid role and user ID are provided")
    void should_UpdateUserRole_When_ValidRoleAndUserIdAreProvided() {
        // Given
        Role newRole = Role.ADMIN;
        
        when(userRepository.findById(userId)).thenReturn(Optional.of(testUser));
        when(userRepository.saveAndFlush(any(User.class))).thenReturn(testUser);
        
        // When
        RoleUpdateResponse response = userService.updateUserRole(userId, newRole);
        
        // Then
        verify(userRepository).saveAndFlush(userCaptor.capture());
        User updatedUser = userCaptor.getValue();
        
        assertThat(response.isSuccess()).isTrue();
        assertThat(response.getUserId()).isEqualTo(userId);
        assertThat(updatedUser.getRole()).isEqualTo(newRole);
    }
    
    @Test
    @DisplayName("Should return error response when updating role for non-existent user")
    void should_ReturnErrorResponse_When_UpdatingRoleForNonExistentUser() {
        // Given
        UUID nonExistentId = UUID.randomUUID();
        Role newRole = Role.ADMIN;
        
        when(userRepository.findById(nonExistentId))
                .thenReturn(Optional.empty());
        
        // When
        RoleUpdateResponse response = userService.updateUserRole(nonExistentId, newRole);
        
        // Then
        assertThat(response.isSuccess()).isFalse();
        assertThat(response.getMessage()).contains("User not found");
    }
    
    @Test
    @DisplayName("Should toggle user ban when valid user ID is provided")
    void should_ToggleUserBan_When_ValidUserIdIsProvided() {
        // Given
        testUser.setBanned(false);
        
        when(userRepository.findById(userId)).thenReturn(Optional.of(testUser));
        when(userRepository.save(any(User.class))).thenReturn(testUser);
        
        // When
        BanStatusResponse response = userService.toggleUserBan(userId);
        
        // Then
        verify(userRepository).save(userCaptor.capture());
        User savedUser = userCaptor.getValue();
        
        assertThat(response.isSuccess()).isTrue();
        assertThat(response.isBanned()).isTrue();
        assertThat(savedUser.isBanned()).isTrue();
    }
    
    @Test
    @DisplayName("Should invalidate tokens when banning a user")
    void should_InvalidateTokens_When_BanningUser() {
        // Given
        testUser.setBanned(false);
        
        when(userRepository.findById(userId)).thenReturn(Optional.of(testUser));
        when(userRepository.save(any(User.class))).thenReturn(testUser);
        
        // When
        userService.toggleUserBan(userId);
        
        // Then
        verify(tokenService).invalidateUserTokens(userId);
    }
    
    @Test
    @DisplayName("Should return user by ID when user exists")
    void should_ReturnUserById_When_UserExists() {
        // Given
        when(userRepository.findById(userId)).thenReturn(Optional.of(testUser));
        
        // When
        UserResponse result = userService.getUserById(userId);
        
        // Then
        assertThat(result).isNotNull();
        assertThat(result.getId()).isEqualTo(userId);
        assertThat(result.getUsername()).isEqualTo(testUser.getUsername());
    }
    
    @Test
    @DisplayName("Should throw ResourceNotFoundException when user with ID does not exist")
    void should_ThrowResourceNotFoundException_When_UserWithIdDoesNotExist() {
        // Given
        UUID nonExistentId = UUID.randomUUID();
        
        when(userRepository.findById(nonExistentId)).thenReturn(Optional.empty());
        
        // When/Then
        assertThatThrownBy(() -> userService.getUserById(nonExistentId))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessageContaining("User not found");
    }
    
    @Test
    @DisplayName("Should return user by username when user exists")
    void should_ReturnUserByUsername_When_UserExists() {
        // Given
        String username = "testuser";
        
        when(userRepository.findByUsername(username)).thenReturn(Optional.of(testUser));
        
        // When
        UserResponse result = userService.getUserByUsername(username);
        
        // Then
        assertThat(result).isNotNull();
        assertThat(result.getUsername()).isEqualTo(username);
    }
    
    @Test
    @DisplayName("Should return user by email when user exists")
    void should_ReturnUserByEmail_When_UserExists() {
        // Given
        String email = "test@example.com";
        
        when(userRepository.findByEmail(email)).thenReturn(Optional.of(testUser));
        
        // When
        UserResponse result = userService.getUserByEmail(email);
        
        // Then
        assertThat(result).isNotNull();
        assertThat(result.getEmail()).isEqualTo(email);
    }
    
    @Test
    @DisplayName("Should check if username exists correctly")
    void should_CheckIfUsernameExists_Correctly() {
        // Given
        String username = "existingUsername";
        
        when(userRepository.existsByUsername(username)).thenReturn(true);
        
        // When
        boolean result = userService.existsByUsername(username);
        
        // Then
        assertThat(result).isTrue();
    }
    
    @Test
    @DisplayName("Should update user profile when valid request is provided")
    void should_UpdateUserProfile_When_ValidRequestIsProvided() {
        // Given
        String currentUsername = "testuser";
        String newUsername = "newUsername";
        ProfileUpdateRequest request = new ProfileUpdateRequest();
        request.setUsername(newUsername);
        
        when(userRepository.findByUsername(currentUsername)).thenReturn(Optional.of(testUser));
        when(userRepository.existsByUsername(newUsername)).thenReturn(false);
        when(userRepository.save(any(User.class))).thenReturn(testUser);
        
        // When
        UserResponse result = userService.updateProfile(currentUsername, request);
        
        // Then
        verify(userRepository).save(userCaptor.capture());
        User savedUser = userCaptor.getValue();
        verify(userDetailsService).handleUsernameChange(eq(currentUsername), eq(newUsername), any(UUID.class));
        
        assertThat(result).isNotNull();
        assertThat(savedUser.getUsername()).isEqualTo(newUsername);
    }
    
    @Test
    @DisplayName("Should throw IllegalArgumentException when updating profile with taken username")
    void should_ThrowIllegalArgumentException_When_UpdatingProfileWithTakenUsername() {
        // Given
        String currentUsername = "testuser";
        String takenUsername = "takenUsername";
        ProfileUpdateRequest request = new ProfileUpdateRequest();
        request.setUsername(takenUsername);
        
        when(userRepository.findByUsername(currentUsername)).thenReturn(Optional.of(testUser));
        when(userRepository.existsByUsername(takenUsername)).thenReturn(true);
        
        // When/Then
        assertThatThrownBy(() -> userService.updateProfile(currentUsername, request))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Username is already taken");
    }
    
    @Test
    @DisplayName("Should check username availability correctly")
    void should_CheckUsernameAvailability_Correctly() {
        // Given
        String availableUsername = "availableUsername";
        
        when(userRepository.existsByUsername(availableUsername)).thenReturn(false);
        
        // When
        UsernameAvailabilityResponse response = userService.checkUsernameAvailability(availableUsername);
        
        // Then
        assertThat(response).isNotNull();
        assertThat(response.getUsername()).isEqualTo(availableUsername);
        assertThat(response.isAvailable()).isTrue();
    }
    
    @Test
    @DisplayName("Should detect current user correctly when user is authenticated")
    void should_DetectCurrentUser_When_UserIsAuthenticated() {
        // Given
        UUID currentUserId = userId;
        UserPrincipal userPrincipal = new UserPrincipal(testUser);
        
        SecurityContextHolder.setContext(securityContext);
        when(securityContext.getAuthentication()).thenReturn(authentication);
        when(authentication.isAuthenticated()).thenReturn(true);
        when(authentication.getPrincipal()).thenReturn(userPrincipal);
        
        // When
        boolean result = userService.isCurrentUser(currentUserId);
        
        // Then
        assertThat(result).isTrue();
    }
    
    @Test
    @DisplayName("Should return username by user ID when user exists")
    void should_ReturnUsernameByUserId_When_UserExists() {
        // Given
        String username = "testuser";
        
        when(userRepository.findUsernameById(userId)).thenReturn(Optional.of(username));
        
        // When
        String result = userService.getUsernameById(userId);
        
        // Then
        assertThat(result).isEqualTo(username);
    }
} 