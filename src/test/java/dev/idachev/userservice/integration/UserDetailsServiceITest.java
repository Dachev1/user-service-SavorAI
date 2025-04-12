package dev.idachev.userservice.integration;

import dev.idachev.userservice.model.Role;
import dev.idachev.userservice.model.User;
import dev.idachev.userservice.repository.UserRepository;
import dev.idachev.userservice.security.UserPrincipal;
import dev.idachev.userservice.service.UserDetailsService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@SpringBootTest
@ActiveProfiles("test")
@Transactional
public class UserDetailsServiceITest {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private UserDetailsService userDetailsService;

    @MockitoBean
    private CacheManager cacheManager;

    private Cache userDetailsCache;
    private Cache usersCache;

    private User testUser;
    private UUID testUserId;

    @BeforeEach
    void setUp() {
        // Create and configure cache mocks
        userDetailsCache = mock(Cache.class);
        usersCache = mock(Cache.class);
        when(cacheManager.getCache("userDetails")).thenReturn(userDetailsCache);
        when(cacheManager.getCache("users")).thenReturn(usersCache);

        // Clear database
        userRepository.deleteAll();

        // Create test user
        testUser = User.builder()
                .username("testuser")
                .email("test@example.com")
                .password("encodedPassword")
                .role(Role.USER)
                .enabled(true)
                .createdOn(LocalDateTime.now())
                .updatedOn(LocalDateTime.now())
                .build();

        testUser = userRepository.save(testUser);
        testUserId = testUser.getId();
    }

    @Test
    @DisplayName("Should load user by username")
    void testLoadUserByUsername() {
        // When
        UserDetails userDetails = userDetailsService.loadUserByUsername("testuser");

        // Then
        assertThat(userDetails).isInstanceOf(UserPrincipal.class);
        UserPrincipal userPrincipal = (UserPrincipal) userDetails;
        assertThat(userPrincipal.getUsername()).isEqualTo("testuser");
        assertThat(userPrincipal.user().getId()).isEqualTo(testUserId);
    }

    @Test
    @DisplayName("Should load user by email")
    void testLoadUserByEmail() {
        // When
        UserDetails userDetails = userDetailsService.loadUserByUsername("test@example.com");

        // Then
        assertThat(userDetails).isInstanceOf(UserPrincipal.class);
        UserPrincipal userPrincipal = (UserPrincipal) userDetails;
        assertThat(userPrincipal.getUsername()).isEqualTo("testuser");
        assertThat(userPrincipal.user().getEmail()).isEqualTo("test@example.com");
    }

    @Test
    @DisplayName("Should throw exception when username not found")
    void testLoadUserByUsernameNotFound() {
        assertThatThrownBy(() -> userDetailsService.loadUserByUsername("nonexistent"))
                .isInstanceOf(UsernameNotFoundException.class)
                .hasMessageContaining("User not found with identifier: nonexistent");
    }

    @Test
    @DisplayName("Should load user by ID")
    void testLoadUserById() {
        // When
        UserDetails userDetails = userDetailsService.loadUserById(testUserId);

        // Then
        assertThat(userDetails).isInstanceOf(UserPrincipal.class);
        UserPrincipal userPrincipal = (UserPrincipal) userDetails;
        assertThat(userPrincipal.getUsername()).isEqualTo("testuser");
        assertThat(userPrincipal.user().getId()).isEqualTo(testUserId);
    }

    @Test
    @DisplayName("Should throw exception when user ID not found")
    void testLoadUserByIdNotFound() {
        // Given
        UUID nonExistentId = UUID.randomUUID();

        // When/Then
        assertThatThrownBy(() -> userDetailsService.loadUserById(nonExistentId))
                .isInstanceOf(UsernameNotFoundException.class)
                .hasMessageContaining("User not found with ID: " + nonExistentId);
    }

    @Test
    @DisplayName("Should clear user details cache by username")
    void testClearUserDetailsCache() {
        // When
        userDetailsService.clearUserDetailsCache("testuser");

        // Then
        verify(userDetailsCache).evict("testuser");
    }

    @Test
    @DisplayName("Should clear user details cache by ID")
    void testClearUserDetailsCacheById() {
        // When
        userDetailsService.clearUserDetailsCacheById(testUserId);

        // Then
        verify(userDetailsCache).evict("id_" + testUserId);
    }

    @Test
    @DisplayName("Should handle username change with cache eviction")
    void testHandleUsernameChange() {
        // When
        userDetailsService.handleUsernameChange("testuser", "newusername", testUserId);

        // Then
        // Verify cache evictions
        verify(userDetailsCache).evict("testuser");
        verify(userDetailsCache).evict("newusername");
        verify(userDetailsCache).evict("id_" + testUserId);

        verify(usersCache).evict("testuser");
        verify(usersCache).evict("newusername");
        verify(usersCache).evict("username_" + "testuser");
        verify(usersCache).evict("username_" + "newusername");
        verify(usersCache).evict("exists_username_" + "testuser");
        verify(usersCache).evict("exists_username_" + "newusername");
        verify(usersCache).evict(testUserId.toString());

        // Verify user is logged out
        User updatedUser = userRepository.findById(testUserId).orElseThrow();
        assertThat(updatedUser.isLoggedIn()).isFalse();
    }

    @Test
    @DisplayName("Should handle cache eviction when cache is null")
    void testHandleUsernameChangeWithNullCache() {
        // Given
        when(cacheManager.getCache("userDetails")).thenReturn(null);
        when(cacheManager.getCache("users")).thenReturn(null);

        // When
        userDetailsService.handleUsernameChange("testuser", "newusername", testUserId);

        // Then
        // Verify user is logged out
        User updatedUser = userRepository.findById(testUserId).orElseThrow();
        assertThat(updatedUser.isLoggedIn()).isFalse();
    }
}