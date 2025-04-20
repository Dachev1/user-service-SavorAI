package dev.idachev.userservice.service;

import dev.idachev.userservice.exception.OperationForbiddenException;
import dev.idachev.userservice.exception.ResourceNotFoundException;
import dev.idachev.userservice.web.mapper.DtoMapper;
import dev.idachev.userservice.web.mapper.EntityMapper;
import dev.idachev.userservice.model.Role;
import dev.idachev.userservice.model.User;
import dev.idachev.userservice.repository.UserRepository;
import dev.idachev.userservice.security.UserPrincipal;
import dev.idachev.userservice.web.dto.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.cache.annotation.Caching;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Service for user management operations
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final CacheManager cacheManager;
    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;
    private final TokenService tokenService;
    private final VerificationService verificationService;

    /**
     * Registers a new user
     */
    @Transactional
    public User registerUser(RegisterRequest request) {
        User newUser = EntityMapper.mapToNewUser(
                request,
                passwordEncoder,
                verificationService.generateVerificationToken()
        );
        try {
            return userRepository.save(newUser);
        } catch (Exception e) {
            log.error("Unexpected error during user registration for username {}: {}", request.username(), e.getMessage(), e);
            throw new RuntimeException("An unexpected error occurred during registration.", e);
        }
    }

    /**
     * Gets all users in the system (admin only)
     */
    @Transactional(readOnly = true)
    @Cacheable(value = "users", key = "'allUsers'")
    public List<UserResponse> getAllUsers() {
        return userRepository.findAll().stream()
                .map(DtoMapper::mapToUserResponse)
                .collect(Collectors.toList());
    }

    /**
     * Updates a user's role. Invalidates user tokens.
     * Throws ResourceNotFoundException if user not found.
     * Throws OperationForbiddenException if admin tries to change own role.
     * Re-throws exceptions from tokenService.invalidateUserTokens.
     */
    @Transactional
    @CacheEvict(value = {"users", "usernames"}, key = "#userId")
    public User updateUserRole(UUID userId, Role role) {
        if (isCurrentUser(userId)) {
            throw new OperationForbiddenException("Admins cannot change their own role");
        }

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with id: " + userId));

        user.updateRole(role);
        User savedUser = userRepository.save(user);

        tokenService.invalidateUserTokens(userId);

        evictCollectionCaches();

        return savedUser;
    }

    /**
     * Toggles a user's ban status. Invalidates tokens if banned.
     * Throws ResourceNotFoundException if user not found.
     * Throws OperationForbiddenException if admin tries to ban self.
     * Re-throws exceptions from tokenService.invalidateUserTokens.
     */
    @Transactional
    @CacheEvict(value = {"users", "usernames"}, key = "#userId")
    public User toggleUserBan(UUID userId) {
        if (isCurrentUser(userId)) {
            throw new OperationForbiddenException("Admins cannot ban themselves");
        }

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with id: " + userId));

        if (user.isBanned()) {
            user.unban();
        } else {
            user.ban();
        }
        User savedUser = userRepository.save(user);

        if (savedUser.isBanned()) {
            tokenService.invalidateUserTokens(userId);
        }

        evictCollectionCaches();

        return savedUser;
    }

    /**
     * Finds a user by ID
     */
    @Transactional(readOnly = true)
    @Cacheable(value = "users", key = "#userId")
    public UserResponse getUserById(UUID userId) {
        return userRepository.findById(userId)
                .map(DtoMapper::mapToUserResponse)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with id: " + userId));
    }

    /**
     * Finds a user by username
     */
    @Transactional(readOnly = true)
    @Cacheable(value = "users", key = "'username_' + #username")
    public UserResponse getUserByUsername(String username) {
        return userRepository.findByUsername(username)
                .map(DtoMapper::mapToUserResponse)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with username: " + username));
    }

    /**
     * Finds a user by email
     */
    @Transactional(readOnly = true)
    @Cacheable(value = "users", key = "'email_' + #email")
    public UserResponse getUserByEmail(String email) {
        return userRepository.findByEmail(email)
                .map(DtoMapper::mapToUserResponse)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with email: " + email));
    }

    /**
     * Checks if a username exists
     */
    @Transactional(readOnly = true)
    @Cacheable(value = "users", key = "'exists_username_' + #username")
    public boolean existsByUsername(String username) {
        return userRepository.existsByUsername(username);
    }

    /**
     * Finds a user entity by username
     */
    @Transactional(readOnly = true)
    @Cacheable(value = "users", key = "#username")
    public User findByUsername(String username) {
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with username: " + username));
    }

    /**
     * Updates a user's profile (currently only username).
     */
    @Transactional
    @Caching(evict = {
            @CacheEvict(value = "users", key = "'username_' + #currentUsername"),
            @CacheEvict(value = "usernames", key = "#currentUsername")
    })
    public UserResponse updateProfile(String currentUsername, ProfileUpdateRequest request) {
        User user = findByUsername(currentUsername);
        boolean usernameChanged = false;
        String newUsername = request.getUsername();

        if (newUsername != null && !newUsername.isBlank() && !newUsername.equals(currentUsername)) {
            if (userRepository.existsByUsername(newUsername)) {
                throw new IllegalArgumentException("Username is already taken");
            }
            user.updateUsername(newUsername);
            usernameChanged = true;
        }

        User savedUser = userRepository.save(user);

        if (usernameChanged) {
            log.debug("Manually evicting caches for username change: {} -> {}", currentUsername, savedUser.getUsername());
            var usersCache = cacheManager.getCache("users");
            if (usersCache != null) {
                usersCache.evict("'username_'" + currentUsername);
                usersCache.evict("'username_'" + savedUser.getUsername());
                usersCache.evict(savedUser.getId());
            }
            var usernamesCache = cacheManager.getCache("usernames");
            if (usernamesCache != null) {
                usernamesCache.evict(savedUser.getId());
            }
            evictCollectionCaches();
        }

        return DtoMapper.mapToUserResponse(savedUser);
    }

    /**
     * Checks if a username is available
     */
    @Transactional(readOnly = true)
    public UsernameAvailabilityResponse checkUsernameAvailability(String username) {
        boolean isAvailable = !existsByUsername(username);
        return UsernameAvailabilityResponse.of(username, isAvailable);
    }

    /**
     * Deletes a user from the system (admin only)
     */
    @Transactional
    @CacheEvict(value = {"users", "usernames"}, allEntries = true)
    public void deleteUser(UUID userId) {
        if (isCurrentUser(userId)) {
            throw new OperationForbiddenException("Admins cannot delete themselves");
        }
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with id: " + userId));

        tokenService.invalidateUserTokens(userId);

        userRepository.delete(user);
        log.info("Deleted user with ID: {}", userId);
        evictCollectionCaches();
    }

    /**
     * Gets user statistics (admin only)
     */
    @Transactional(readOnly = true)
    public UserStatsResponse getUserStats() {
        long totalUsers = userRepository.count();
        long activeUsers = userRepository.countByBannedFalse();
        long bannedUsers = userRepository.countByBannedTrue();
        long verifiedUsers = userRepository.countByEnabledTrue();
        long adminUsers = userRepository.countByRole(Role.ADMIN);

        return UserStatsResponse.builder()
                .totalUsers(totalUsers)
                .activeUsers(activeUsers)
                .bannedUsers(bannedUsers)
                .verifiedUsers(verifiedUsers)
                .adminUsers(adminUsers)
                .timestamp(LocalDateTime.now())
                .build();
    }

    /**
     * Check if a user ID belongs to the currently authenticated user
     */
    public boolean isCurrentUser(UUID userId) {
        if (userId == null) {
            return false;
        }

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            return false;
        }

        Object principal = authentication.getPrincipal();
        UUID currentUserId = null;

        if (principal instanceof UserPrincipal userPrincipal) {
            currentUserId = userPrincipal.user().getId();
        } else if (principal instanceof UserDetails userDetails) {
            User user = userRepository.findByUsername(userDetails.getUsername()).orElse(null);
            if (user != null) {
                currentUserId = user.getId();
            }
        }

        return userId.equals(currentUserId);
    }

    /**
     * Get just the username by user ID
     */
    @Transactional(readOnly = true)
    @Cacheable(value = "usernames", key = "#userId")
    public String getUsernameById(UUID userId) {
        return userRepository.findUsernameById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with id: " + userId));
    }

    private void evictCollectionCaches() {
        Cache usersCache = cacheManager.getCache("users");
        if (usersCache != null) {
            usersCache.evict("'allUsers'");
        }
        Cache statsCache = cacheManager.getCache("userStats");
        if (statsCache != null) {
            statsCache.clear();
        }
        // Also clear the usernames cache as user changes (delete, ban, role) affect it
        Cache usernamesCache = cacheManager.getCache("usernames");
        if (usernamesCache != null) {
            usernamesCache.clear();
        }
    }
} 
