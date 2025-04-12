package dev.idachev.userservice.service;

import dev.idachev.userservice.exception.ResourceNotFoundException;
import dev.idachev.userservice.model.Role;
import dev.idachev.userservice.model.User;
import dev.idachev.userservice.repository.UserRepository;
import dev.idachev.userservice.web.dto.GenericResponse;
import dev.idachev.userservice.web.dto.ProfileUpdateRequest;
import dev.idachev.userservice.web.dto.UserResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class UserServiceUTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private AuthenticationService authenticationService;

    @Mock
    private UserDetailsService userDetailsService;

    @Mock
    private CacheManager cacheManager;

    @Mock
    private Cache usersCache;

    @InjectMocks
    private UserService userService;

    private User testUser;
    private UUID testUserId;
    private ProfileUpdateRequest updateRequest;

    @BeforeEach
    void setUp() {
        // Given
        testUserId = UUID.randomUUID();
        testUser = new User();
        testUser.setId(testUserId);
        testUser.setUsername("testuser");
        testUser.setEmail("test@example.com");
        testUser.setPassword("password");
        testUser.setEnabled(true);
        testUser.setBanned(false);
        testUser.setRole(Role.USER);

        updateRequest = new ProfileUpdateRequest();
        updateRequest.setUsername("newusername");
    }

    @Test
    void getAllUsers_ReturnsListOfUsers() {
        // Given
        List<User> users = Arrays.asList(testUser);
        when(userRepository.findAll()).thenReturn(users);

        // When
        List<UserResponse> result = userService.getAllUsers();

        // Then
        assertNotNull(result);
        assertEquals(1, result.size());
        assertEquals(testUser.getUsername(), result.get(0).getUsername());
    }

    @Test
    void setUserRole_WithValidData_UpdatesRole() {
        // Given
        when(userRepository.findById(any(UUID.class))).thenReturn(Optional.of(testUser));
        when(userRepository.saveAndFlush(any(User.class))).thenReturn(testUser);

        // When
        GenericResponse result = userService.setUserRole(testUserId, Role.ADMIN);

        // Then
        assertNotNull(result);
        assertTrue(result.isSuccess());
        assertEquals(200, result.getStatus());
        verify(userRepository).saveAndFlush(any(User.class));
    }

    @Test
    void setUserRole_WithNonexistentUser_ThrowsException() {
        // Given
        when(userRepository.findById(any(UUID.class))).thenReturn(Optional.empty());

        // When/Then
        assertThrows(ResourceNotFoundException.class, () -> 
            userService.setUserRole(testUserId, Role.ADMIN));
    }

    @Test
    void toggleUserBan_WithValidUser_TogglesBanStatus() {
        // Given
        testUser.setBanned(false);
        when(userRepository.findById(any(UUID.class))).thenReturn(Optional.of(testUser));
        
        // Important: Mock the save method to return the test user with modified banned status
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> {
            User savedUser = invocation.getArgument(0);
            // The service will have set banned=true on this user
            return savedUser;
        });
        
        // When
        GenericResponse result = userService.toggleUserBan(testUserId);

        // Then
        assertNotNull(result);
        assertTrue(result.isSuccess());
        assertEquals(200, result.getStatus());
        assertTrue(testUser.isBanned());
        verify(userRepository).save(any(User.class));
    }

    @Test
    void toggleUserBan_WithBannedUser_RemovesBanStatus() {
        // Given
        testUser.setBanned(true);
        when(userRepository.findById(any(UUID.class))).thenReturn(Optional.of(testUser));
        
        // Important: Mock the save method to return the test user with modified banned status
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> {
            User savedUser = invocation.getArgument(0);
            // The service will have set banned=false on this user
            return savedUser;
        });
        
        // When
        GenericResponse result = userService.toggleUserBan(testUserId);

        // Then
        assertNotNull(result);
        assertTrue(result.isSuccess());
        assertEquals(200, result.getStatus());
        assertFalse(testUser.isBanned());
        verify(userRepository).save(any(User.class));
    }

    @Test
    void toggleUserBan_WithNonexistentUser_ThrowsException() {
        // Given
        when(userRepository.findById(any(UUID.class))).thenReturn(Optional.empty());

        // When/Then
        assertThrows(ResourceNotFoundException.class, () -> 
            userService.toggleUserBan(testUserId));
    }

    @Test
    void findUserById_WithValidId_ReturnsUser() {
        // Given
        when(userRepository.findById(any(UUID.class))).thenReturn(Optional.of(testUser));

        // When
        UserResponse result = userService.findUserById(testUserId);

        // Then
        assertNotNull(result);
        assertEquals(testUser.getUsername(), result.getUsername());
        assertEquals(testUser.getEmail(), result.getEmail());
        assertEquals(testUser.isBanned(), result.isBanned());
    }

    @Test
    void findUserById_WithNonexistentId_ThrowsException() {
        // Given
        when(userRepository.findById(any(UUID.class))).thenReturn(Optional.empty());

        // When/Then
        assertThrows(ResourceNotFoundException.class, () -> 
            userService.findUserById(testUserId));
    }

    @Test
    void findUserByUsername_WithValidUsername_ReturnsUser() {
        // Given
        when(userRepository.findByUsername(anyString())).thenReturn(Optional.of(testUser));

        // When
        UserResponse result = userService.findUserByUsername("testuser");

        // Then
        assertNotNull(result);
        assertEquals(testUser.getUsername(), result.getUsername());
        assertEquals(testUser.getEmail(), result.getEmail());
        assertEquals(testUser.isBanned(), result.isBanned());
    }

    @Test
    void findUserByUsername_WithNonexistentUsername_ThrowsException() {
        // Given
        when(userRepository.findByUsername(anyString())).thenReturn(Optional.empty());

        // When/Then
        assertThrows(ResourceNotFoundException.class, () -> 
            userService.findUserByUsername("nonexistent"));
    }

    @Test
    void findUserByEmail_WithValidEmail_ReturnsUser() {
        // Given
        when(userRepository.findByEmail(anyString())).thenReturn(Optional.of(testUser));

        // When
        UserResponse result = userService.findUserByEmail("test@example.com");

        // Then
        assertNotNull(result);
        assertEquals(testUser.getUsername(), result.getUsername());
        assertEquals(testUser.getEmail(), result.getEmail());
        assertEquals(testUser.isBanned(), result.isBanned());
    }

    @Test
    void findUserByEmail_WithNonexistentEmail_ThrowsException() {
        // Given
        when(userRepository.findByEmail(anyString())).thenReturn(Optional.empty());

        // When/Then
        assertThrows(ResourceNotFoundException.class, () -> 
            userService.findUserByEmail("nonexistent@example.com"));
    }

    @Test
    void existsByUsername_WithExistingUsername_ReturnsTrue() {
        // Given
        when(userRepository.existsByUsername(anyString())).thenReturn(true);

        // When
        boolean result = userService.existsByUsername("testuser");

        // Then
        assertTrue(result);
    }

    @Test
    void existsByUsername_WithNonexistentUsername_ReturnsFalse() {
        // Given
        when(userRepository.existsByUsername(anyString())).thenReturn(false);

        // When
        boolean result = userService.existsByUsername("nonexistent");

        // Then
        assertFalse(result);
    }

    @Test
    void updateProfile_WithValidData_UpdatesProfile() {
        // Given
        when(userRepository.findByUsername(anyString())).thenReturn(Optional.of(testUser));
        when(userRepository.existsByUsername(anyString())).thenReturn(false);
        
        // Mock save to return the modified user
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> {
            User user = invocation.getArgument(0);
            return user; // Return the same user that was passed in
        });
        
        // Mock cache manager
        when(cacheManager.getCache("users")).thenReturn(usersCache);
        
        // When
        UserResponse result = userService.updateProfile("testuser", updateRequest);

        // Then
        assertNotNull(result);
        assertEquals("newusername", result.getUsername());
        verify(userRepository).save(any(User.class));
        
        // Verify that at least one of these cache evictions happen - the implementation has multiple eviction calls
        verify(usersCache, atLeastOnce()).evict(anyString());
    }
} 