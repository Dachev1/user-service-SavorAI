package dev.idachev.userservice.service;

import dev.idachev.userservice.config.BaseIntegrationTest;
import dev.idachev.userservice.config.TestDataInitializer;
import dev.idachev.userservice.exception.ResourceNotFoundException;
import dev.idachev.userservice.model.Role;
import dev.idachev.userservice.repository.UserRepository;
import dev.idachev.userservice.web.dto.GenericResponse;
import dev.idachev.userservice.web.dto.ProfileUpdateRequest;
import dev.idachev.userservice.web.dto.RegisterRequest;
import dev.idachev.userservice.web.dto.UserResponse;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration tests for UserService.
 * Uses H2 in-memory database with test profile.
 */
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
class UserServiceIntegrationTest extends BaseIntegrationTest {

    @Autowired
    private UserService userService;

    @Autowired
    private UserRepository userRepository;

    @Test
    @Transactional
    void getAllUsers_ReturnsAllUsersInDatabase() {
        // Given: Pre-initialized test data by TestDataInitializer

        // When: We call getAllUsers
        List<UserResponse> allUsers = userService.getAllUsers();

        // Then: We should get all users from database
        assertNotNull(allUsers);
        // Should find at least 4 users from TestDataInitializer
        assertTrue(allUsers.size() >= 4);
        // Verify some expected users exist by username
        assertTrue(allUsers.stream().anyMatch(u -> u.getUsername().equals("admin")));
        assertTrue(allUsers.stream().anyMatch(u -> u.getUsername().equals("user")));
    }

    @Test
    @Transactional
    void findUserById_WithValidId_ReturnsCorrectUser() {
        // Given: A known user ID from test data
        UUID userId = TestDataInitializer.ADMIN_USER_ID;

        // When: We find the user by ID
        UserResponse user = userService.findUserById(userId);

        // Then: The correct user should be returned
        assertNotNull(user);
        assertEquals("admin", user.getUsername());
        assertEquals("admin@example.com", user.getEmail());
        assertEquals("ADMIN", user.getRole());
    }

    @Test
    @Transactional
    void findUserById_WithInvalidId_ThrowsException() {
        // Given: A non-existent user ID
        UUID nonExistentId = UUID.randomUUID();

        // When/Then: Finding the user should throw an exception
        assertThrows(ResourceNotFoundException.class, () -> 
            userService.findUserById(nonExistentId));
    }

    @Test
    @Transactional
    void registerUser_WithValidData_CreatesNewUser() {
        // Given: Valid registration data
        RegisterRequest request = new RegisterRequest();
        request.setUsername("newuser");
        request.setEmail("newuser@example.com");
        request.setPassword("Password123!");

        // When: We register a new user
        var savedUser = userService.registerUser(request);

        // Then: User should be created with correct data
        assertNotNull(savedUser);
        assertNotNull(savedUser.getId());
        assertEquals("newuser", savedUser.getUsername());
        assertEquals("newuser@example.com", savedUser.getEmail());
        // Verify the user exists in the database
        assertTrue(userRepository.existsByUsername("newuser"));
    }

    @Test
    @Transactional
    void setUserRole_ChangesUserRole() {
        // Given: A regular user to update
        UUID userId = TestDataInitializer.REGULAR_USER_ID;
        
        // When: We set the user's role to ADMIN
        GenericResponse response = userService.setUserRole(userId, Role.ADMIN);
        
        // Then: The role should be updated successfully
        assertTrue(response.isSuccess());
        // Verify role was updated in database
        var user = userRepository.findById(userId).orElseThrow();
        assertEquals(Role.ADMIN, user.getRole());
    }

    @Test
    @Transactional
    void toggleUserBan_ForUnbannedUser_ShouldBanUser() {
        // Given: A known unbanned user
        UUID userId = TestDataInitializer.REGULAR_USER_ID;
        assertFalse(userRepository.findById(userId).orElseThrow().isBanned());
        
        // When: We toggle the ban status
        GenericResponse response = userService.toggleUserBan(userId);
        
        // Then: The user should now be banned
        assertTrue(response.isSuccess());
        assertTrue(userRepository.findById(userId).orElseThrow().isBanned());
        assertTrue(response.getMessage().contains("banned successfully"));
    }

    @Test
    @Transactional
    void toggleUserBan_ForBannedUser_ShouldUnbanUser() {
        // Given: A known banned user
        UUID userId = TestDataInitializer.BANNED_USER_ID;
        assertTrue(userRepository.findById(userId).orElseThrow().isBanned());
        
        // When: We toggle the ban status
        GenericResponse response = userService.toggleUserBan(userId);
        
        // Then: The user should now be unbanned
        assertTrue(response.isSuccess());
        assertFalse(userRepository.findById(userId).orElseThrow().isBanned());
        assertTrue(response.getMessage().contains("unbanned successfully"));
    }

    @Test
    @Transactional
    void updateProfile_WithUsernameChange_ShouldUpdateUsername() {
        // Given: A known user and a profile update request
        String oldUsername = "user";
        ProfileUpdateRequest request = new ProfileUpdateRequest();
        request.setUsername("updated_user");
        
        // When: We update the profile
        UserResponse response = userService.updateProfile(oldUsername, request);
        
        // Then: The username should be updated
        assertNotNull(response);
        assertEquals("updated_user", response.getUsername());
        // Verify in database
        assertTrue(userRepository.existsByUsername("updated_user"));
        assertFalse(userRepository.existsByUsername(oldUsername));
    }

    @Test
    @Transactional
    void existsByUsername_WithExistingUsername_ReturnsTrue() {
        // Given: A known username
        String username = "admin";
        
        // When: We check if the username exists
        boolean exists = userService.existsByUsername(username);
        
        // Then: It should return true
        assertTrue(exists);
    }

    @Test
    @Transactional
    void existsByUsername_WithNonExistentUsername_ReturnsFalse() {
        // Given: A non-existent username
        String username = "nonexistent_user";
        
        // When: We check if the username exists
        boolean exists = userService.existsByUsername(username);
        
        // Then: It should return false
        assertFalse(exists);
    }
} 