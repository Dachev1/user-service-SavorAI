package dev.idachev.userservice.service;

import dev.idachev.userservice.model.User;
import dev.idachev.userservice.repository.UserRepository;
import dev.idachev.userservice.security.UserPrincipal;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@SpringBootTest
@ActiveProfiles("test")
class UserDetailsServiceUTest {

    @MockitoBean
    private UserRepository userRepository;

    @MockitoBean
    private CacheManager cacheManager;

    private Cache userDetailsCache;

    @Autowired
    private UserDetailsService userDetailsService;

    private User testUser;
    private UUID testUserId;

    @BeforeEach
    void setUp() {
        testUserId = UUID.randomUUID();
        testUser = new User();
        testUser.setId(testUserId);
        testUser.setUsername("testuser");
        testUser.setEmail("test@example.com");
        testUser.setPassword("password");
        testUser.setEnabled(true);

        // Create and setup mocks
        userDetailsCache = mock(Cache.class);
        when(cacheManager.getCache("userDetails")).thenReturn(userDetailsCache);
    }

    @Test
    void loadUserByUsername_WithValidUsername_ReturnsUserDetails() {
        // Given
        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(testUser));

        // When
        UserDetails result = userDetailsService.loadUserByUsername("testuser");

        // Then
        assertNotNull(result);
        assertTrue(result instanceof UserPrincipal);
        assertEquals(testUser.getUsername(), ((UserPrincipal) result).user().getUsername());
    }

    @Test
    void loadUserByUsername_WithValidEmail_ReturnsUserDetails() {
        // Given
        when(userRepository.findByUsername("test@example.com")).thenReturn(Optional.empty());
        when(userRepository.findByEmail("test@example.com")).thenReturn(Optional.of(testUser));

        // When
        UserDetails result = userDetailsService.loadUserByUsername("test@example.com");

        // Then
        assertNotNull(result);
        assertTrue(result instanceof UserPrincipal);
        assertEquals(testUser.getEmail(), ((UserPrincipal) result).user().getEmail());
    }

    @Test
    void loadUserByUsername_WithEmptyUsername_ThrowsException() {
        // When/Then
        assertThrows(UsernameNotFoundException.class, () ->
                userDetailsService.loadUserByUsername(""));
    }

    @Test
    void loadUserByUsername_WithNullUsername_ThrowsException() {
        // When/Then
        assertThrows(IllegalArgumentException.class, () ->
                userDetailsService.loadUserByUsername(null));
    }

    @Test
    void loadUserByUsername_WithNonexistentUser_ThrowsException() {
        // Given
        when(userRepository.findByUsername("nonexistent")).thenReturn(Optional.empty());
        when(userRepository.findByEmail("nonexistent")).thenReturn(Optional.empty());

        // When/Then
        assertThrows(UsernameNotFoundException.class, () ->
                userDetailsService.loadUserByUsername("nonexistent"));
    }

    @Test
    void loadUserById_WithValidId_ReturnsUserDetails() {
        // Given
        when(userRepository.findById(testUserId)).thenReturn(Optional.of(testUser));

        // When
        UserDetails result = userDetailsService.loadUserById(testUserId);

        // Then
        assertNotNull(result);
        assertTrue(result instanceof UserPrincipal);
        assertEquals(testUser.getId(), ((UserPrincipal) result).user().getId());
    }

    @Test
    void loadUserById_WithNonexistentId_ThrowsException() {
        // Given
        UUID nonExistentId = UUID.randomUUID();
        when(userRepository.findById(nonExistentId)).thenReturn(Optional.empty());

        // When/Then
        assertThrows(UsernameNotFoundException.class, () ->
                userDetailsService.loadUserById(nonExistentId));
    }

    @Test
    void clearUserDetailsCache_WithUsername_ClearsCache() {
        // When
        userDetailsService.clearUserDetailsCache("testuser");

        // Then
        verify(userDetailsCache, times(1)).evict("testuser");
    }

    @Test
    void clearUserDetailsCache_WithUserId_ClearsCache() {
        // When
        userDetailsService.clearUserDetailsCacheById(testUserId);

        // Then
        verify(userDetailsCache, times(1)).evict("id_" + testUserId);
    }

    @Test
    void handleUsernameChange_ClearsAllRelevantCaches() {
        // Given
        String oldUsername = "olduser";
        String newUsername = "newuser";
        Cache usersCache = mock(Cache.class);
        when(cacheManager.getCache("userDetails")).thenReturn(userDetailsCache);
        when(cacheManager.getCache("users")).thenReturn(usersCache);

        // When
        userDetailsService.handleUsernameChange(oldUsername, newUsername, testUserId);

        // Then
        verify(userDetailsCache, atLeastOnce()).evict(oldUsername);
        verify(userDetailsCache).evict(newUsername);
        verify(userDetailsCache).evict("id_" + testUserId);
        verify(usersCache, times(7)).evict(anyString());
    }

    @Test
    void handleUsernameChange_WithNullCacheManager_DoesNotThrowException() {
        // Given
        String oldUsername = "olduser";
        String newUsername = "newuser";
        when(cacheManager.getCache("userDetails")).thenReturn(null);
        when(cacheManager.getCache("users")).thenReturn(null);

        // When/Then
        assertDoesNotThrow(() ->
                userDetailsService.handleUsernameChange(oldUsername, newUsername, testUserId));
    }
}