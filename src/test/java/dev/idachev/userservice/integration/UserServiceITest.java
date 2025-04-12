package dev.idachev.userservice.integration;

import dev.idachev.userservice.exception.ResourceNotFoundException;
import dev.idachev.userservice.model.Role;
import dev.idachev.userservice.model.User;
import dev.idachev.userservice.repository.UserRepository;
import dev.idachev.userservice.service.EmailService;
import dev.idachev.userservice.service.TokenService;
import dev.idachev.userservice.service.UserDetailsService;
import dev.idachev.userservice.service.UserService;
import dev.idachev.userservice.web.dto.GenericResponse;
import dev.idachev.userservice.web.dto.ProfileUpdateRequest;
import dev.idachev.userservice.web.dto.RegisterRequest;
import dev.idachev.userservice.web.dto.UserResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@SpringBootTest
@ActiveProfiles("test")
@Transactional
public class UserServiceITest {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private UserService userService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @MockitoBean
    private UserDetailsService userDetailsService;

    @MockitoBean
    private CacheManager cacheManager;

    @MockitoBean
    private EmailService emailService;

    @MockitoBean
    private TokenService tokenService;

    private Cache cache;

    private User testUser;
    private UUID testUserId;

    @BeforeEach
    void setUp() {
        // Create cache mock
        cache = mock(Cache.class);
        
        // Clear any previous test data
        userRepository.deleteAll();
        
        // Mock email service
        when(emailService.generateVerificationToken()).thenReturn("test-verification-token");
        
        // Mock cache manager
        when(cacheManager.getCache(anyString())).thenReturn(cache);
        doNothing().when(cache).evict(any());
        
        // Create test user
        RegisterRequest registerRequest = new RegisterRequest();
        registerRequest.setUsername("testuser");
        registerRequest.setEmail("test@example.com");
        registerRequest.setPassword("Password123!");
        
        testUser = userService.registerUser(registerRequest);
        testUserId = testUser.getId();
        
        // Clear security context
        SecurityContextHolder.clearContext();
    }

    @Test
    @DisplayName("Should register a new user successfully")
    void testRegisterUser() {
        // Given
        RegisterRequest registerRequest = new RegisterRequest();
        registerRequest.setUsername("newuser");
        registerRequest.setEmail("new@example.com");
        registerRequest.setPassword("Password123!");

        // When
        User newUser = userService.registerUser(registerRequest);

        // Then
        assertThat(newUser).isNotNull();
        assertThat(newUser.getUsername()).isEqualTo("newuser");
        assertThat(newUser.getEmail()).isEqualTo("new@example.com");
        assertThat(newUser.getRole()).isEqualTo(Role.USER);
        assertThat(newUser.isEnabled()).isFalse(); // User should start as disabled until email verification
        assertThat(passwordEncoder.matches("Password123!", newUser.getPassword())).isTrue();

        // Verify it was saved to the database
        Optional<User> savedUser = userRepository.findByUsername("newuser");
        assertThat(savedUser).isPresent();
    }

    @Test
    @DisplayName("Should find user by ID")
    void testFindUserById() {
        // When
        UserResponse foundUser = userService.findUserById(testUserId);

        // Then
        assertThat(foundUser).isNotNull();
        assertThat(foundUser.getId()).isEqualTo(testUserId);
        assertThat(foundUser.getUsername()).isEqualTo("testuser");
        assertThat(foundUser.getEmail()).isEqualTo("test@example.com");
    }

    @Test
    @DisplayName("Should throw exception when user ID not found")
    void testFindUserByIdNotFound() {
        // Given
        UUID nonExistentId = UUID.randomUUID();

        // When/Then
        assertThatThrownBy(() -> userService.findUserById(nonExistentId))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessageContaining("User not found with id: " + nonExistentId);
    }

    @Test
    @DisplayName("Should find user by username")
    void testFindUserByUsername() {
        // When
        UserResponse foundUser = userService.findUserByUsername("testuser");

        // Then
        assertThat(foundUser).isNotNull();
        assertThat(foundUser.getUsername()).isEqualTo("testuser");
    }

    @Test
    @DisplayName("Should throw exception when username not found")
    void testFindUserByUsernameNotFound() {
        // When/Then
        assertThatThrownBy(() -> userService.findUserByUsername("nonexistent"))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessageContaining("User not found with username: nonexistent");
    }

    @Test
    @DisplayName("Should find user by email")
    void testFindUserByEmail() {
        // When
        UserResponse foundUser = userService.findUserByEmail("test@example.com");

        // Then
        assertThat(foundUser).isNotNull();
        assertThat(foundUser.getEmail()).isEqualTo("test@example.com");
    }

    @Test
    @DisplayName("Should return all users")
    void testGetAllUsers() {
        // Given
        RegisterRequest user2Request = new RegisterRequest();
        user2Request.setUsername("user2");
        user2Request.setEmail("user2@example.com");
        user2Request.setPassword("Password123!");
        userService.registerUser(user2Request);

        // When
        List<UserResponse> allUsers = userService.getAllUsers();

        // Then
        assertThat(allUsers).hasSize(2);
        assertThat(allUsers).extracting(UserResponse::getUsername)
                .containsExactlyInAnyOrder("testuser", "user2");
    }

    @Test
    @DisplayName("Should set user role")
    void testSetUserRole() {
        // When
        GenericResponse response = userService.setUserRole(testUserId, Role.ADMIN);

        // Then
        assertThat(response.isSuccess()).isTrue();
        assertThat(response.getMessage()).contains("User role updated successfully");

        // Verify user role was updated
        User updatedUser = userRepository.findById(testUserId).orElseThrow();
        assertThat(updatedUser.getRole()).isEqualTo(Role.ADMIN);
    }

    @Test
    @DisplayName("Should update user role with token refresh")
    void testUpdateUserRoleWithTokenRefresh() {
        // When
        GenericResponse response = userService.updateUserRoleWithTokenRefresh(testUserId, Role.ADMIN);

        // Then
        assertThat(response.isSuccess()).isTrue();
        assertThat(response.getMessage()).contains("User role updated successfully");

        // Verify user role was updated
        User updatedUser = userRepository.findById(testUserId).orElseThrow();
        assertThat(updatedUser.getRole()).isEqualTo(Role.ADMIN);

        // Verify token service was called
        verify(tokenService).invalidateUserTokens(testUserId);
    }

    @Test
    @DisplayName("Should toggle user ban status")
    void testToggleUserBan() {
        // Given
        assertThat(testUser.isBanned()).isFalse(); // Initial state

        // When
        GenericResponse response = userService.toggleUserBan(testUserId);

        // Then
        assertThat(response.isSuccess()).isTrue();
        assertThat(response.getMessage()).contains("User banned successfully");

        // Verify user was banned
        User updatedUser = userRepository.findById(testUserId).orElseThrow();
        assertThat(updatedUser.isBanned()).isTrue();

        // Toggle again
        response = userService.toggleUserBan(testUserId);

        // Verify user was unbanned
        assertThat(response.getMessage()).contains("User unbanned successfully");
        updatedUser = userRepository.findById(testUserId).orElseThrow();
        assertThat(updatedUser.isBanned()).isFalse();
    }

    @Test
    @DisplayName("Should check if username exists")
    void testExistsByUsername() {
        // When/Then
        assertThat(userService.existsByUsername("testuser")).isTrue();
        assertThat(userService.existsByUsername("nonexistent")).isFalse();
    }

    @Test
    @DisplayName("Should check username availability")
    void testCheckUsernameAvailability() {
        // When
        GenericResponse available = userService.checkUsernameAvailability("newusername");
        GenericResponse notAvailable = userService.checkUsernameAvailability("testuser");

        // Then
        assertThat(available.isSuccess()).isTrue();
        assertThat(available.getMessage()).contains("Username is available");

        assertThat(notAvailable.isSuccess()).isFalse();
        assertThat(notAvailable.getMessage()).contains("Username is already taken");
    }

    @Test
    @DisplayName("Should update user profile")
    void testUpdateProfile() {
        // Given
        ProfileUpdateRequest updateRequest = new ProfileUpdateRequest();
        updateRequest.setUsername("updateduser");

        // When
        UserResponse updatedUser = userService.updateProfile("testuser", updateRequest);

        // Then
        assertThat(updatedUser.getUsername()).isEqualTo("updateduser");

        // Verify user was updated in database
        User savedUser = userRepository.findById(testUserId).orElseThrow();
        assertThat(savedUser.getUsername()).isEqualTo("updateduser");

        // Verify userDetailsService was called
        verify(userDetailsService).handleUsernameChange("testuser", "updateduser", testUserId);
    }

    @Test
    @DisplayName("Should determine if current user matches ID")
    void testIsCurrentUser() {
        // Given
        SecurityContext securityContext = mock(SecurityContext.class);
        Authentication authentication = mock(Authentication.class);
        UserDetails userDetails = mock(UserDetails.class);

        SecurityContextHolder.setContext(securityContext);
        when(securityContext.getAuthentication()).thenReturn(authentication);
        when(authentication.isAuthenticated()).thenReturn(true);
        when(authentication.getPrincipal()).thenReturn(userDetails);
        when(userDetails.getUsername()).thenReturn("testuser");

        // When/Then
        assertThat(userService.isCurrentUser(testUserId)).isTrue();
        assertThat(userService.isCurrentUser(UUID.randomUUID())).isFalse();
    }

    @Test
    @DisplayName("Should handle null username in getUserByUsername")
    void testGetUserByUsernameWithNull() {
        // When
        User result = userService.getUserByUsername(null);

        // Then
        assertThat(result).isNull();
    }

    @Test
    @DisplayName("Should handle empty username in getUserByUsername")
    void testGetUserByUsernameWithEmpty() {
        // When
        User result = userService.getUserByUsername("");

        // Then
        assertThat(result).isNull();
    }
} 