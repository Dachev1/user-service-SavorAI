package dev.idachev.userservice.service;

import dev.idachev.userservice.exception.ResourceNotFoundException;
import dev.idachev.userservice.mapper.DtoMapper;
import dev.idachev.userservice.mapper.EntityMapper;
import dev.idachev.userservice.model.Role;
import dev.idachev.userservice.model.User;
import dev.idachev.userservice.repository.UserRepository;
import dev.idachev.userservice.security.UserPrincipal;
import dev.idachev.userservice.service.EmailService;
import dev.idachev.userservice.service.TokenService;
import dev.idachev.userservice.web.dto.AuthResponse;
import dev.idachev.userservice.web.dto.GenericResponse;
import dev.idachev.userservice.web.dto.ProfileUpdateRequest;
import dev.idachev.userservice.web.dto.RegisterRequest;
import dev.idachev.userservice.web.dto.UserResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Service for user management operations
 */
@Slf4j
@Service
public class UserService {

    private final UserRepository userRepository;
    private final dev.idachev.userservice.service.UserDetailsService userDetailsService;
    private final CacheManager cacheManager;
    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;
    private final TokenService tokenService;

    @Autowired
    public UserService(UserRepository userRepository,
                      dev.idachev.userservice.service.UserDetailsService userDetailsService,
                      CacheManager cacheManager, 
                      PasswordEncoder passwordEncoder,
                      EmailService emailService,
                      TokenService tokenService) {
        this.userRepository = userRepository;
        this.userDetailsService = userDetailsService;
        this.cacheManager = cacheManager;
        this.passwordEncoder = passwordEncoder;
        this.emailService = emailService;
        this.tokenService = tokenService;
    }

    /**
     * Registers a new user and saves them to the database
     *
     * @param request The registration request
     * @return The saved user entity
     */
    @Transactional
    public User registerUser(RegisterRequest request) {
        log.debug("Creating new user with request: {}", request);

        // Create the new user entity
        User newUser = createNewUser(request);

        // Save the user to the database
        User savedUser = userRepository.save(newUser);
        log.info("New user created with ID: {}", savedUser.getId());

        return savedUser;
    }

    /**
     * Creates a new user entity from the registration request
     */
    private User createNewUser(RegisterRequest request) {
        String verificationToken = emailService.generateVerificationToken();
        return EntityMapper.mapToNewUser(request, passwordEncoder, verificationToken);
    }

    /**
     * Gets all users in the system (admin only)
     */
    @Transactional(readOnly = true)
    @Cacheable(value = "users", key = "'allUsers'")
    public List<UserResponse> getAllUsers() {
        log.info("Retrieving all users from the system");
        return userRepository.findAll().stream()
                .map(DtoMapper::mapToUserResponse)
                .collect(Collectors.toList());
    }

    /**
     * Sets a user's role (admin only)
     */
    @Transactional
    @CacheEvict(value = "users", allEntries = true)
    public GenericResponse setUserRole(UUID userId, Role role) {
        log.info("Setting role {} for user {}", role, userId);

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with id: " + userId));

        // Store old role for logging
        Role oldRole = user.getRole();

        // Set new role and update timestamps
        user.setRole(role);
        user.setUpdatedOn(LocalDateTime.now());

        // Explicitly flush to ensure immediate persistence
        userRepository.saveAndFlush(user);

        // Verify the change was persisted
        User verifiedUser = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with id: " + userId));

        if (!verifiedUser.getRole().equals(role)) {
            log.error("Role change verification failed. Expected: {}, Actual: {}", role, verifiedUser.getRole());
            throw new RuntimeException("Role change failed to persist");
        }

        log.info("Successfully updated role from {} to {} for user {}", oldRole, role, userId);
        return GenericResponse.builder()
                .status(200)
                .message("User role updated successfully")
                .timestamp(LocalDateTime.now())
                .success(true)
                .build();
    }

    /**
     * Updates a user's role and refreshes their token
     * This method combines the role update logic and token refresh
     * 
     * @param userId User ID to update
     * @param role New role to assign
     * @return GenericResponse with the result of the operation
     */
    @Transactional
    @CacheEvict(value = "users", allEntries = true)
    public GenericResponse updateUserRoleWithTokenRefresh(UUID userId, Role role) {
        log.info("Updating role with token refresh for user {} to {}", userId, role);
        
        // First update the role in the database
        GenericResponse roleUpdateResponse = setUserRole(userId, role);
        
        // If the database update was successful, proceed with token refresh
        if (roleUpdateResponse.isSuccess()) {
            try {
                // Get fresh user data from database
                User user = userRepository.findById(userId)
                    .orElseThrow(() -> new ResourceNotFoundException("User not found with id: " + userId));

                // Generate new token with updated role
                String newToken = tokenService.generateToken(new UserPrincipal(user));
                
                // Blacklist all existing tokens for this user
                blacklistUserTokens(userId);
                
                log.info("Role change with token refresh completed successfully for user {}", userId);
            } catch (Exception e) {
                log.error("Error during token refresh: {}", e.getMessage());
                // Even if token refresh fails, the role change was successful in the database
                // Include this information in the response
                roleUpdateResponse.setMessage(roleUpdateResponse.getMessage() + 
                    " (Note: Token refresh failed, user will need to log out and back in)");
            }
        }
        
        return roleUpdateResponse;
    }
    
    /**
     * Blacklist all tokens for a specific user
     */
    private void blacklistUserTokens(UUID userId) {
        try {
            // Create a special blacklist entry that marks all tokens for this user as invalid
            String userSpecificKey = "user_tokens_invalidated:" + userId.toString();

            // Set blacklist entry with a long expiry (24 hours)
            long expiryTime = System.currentTimeMillis() + (24 * 60 * 60 * 1000);
            tokenService.blacklistToken(userSpecificKey);

            log.info("All tokens blacklisted for user ID: {}", userId);
        } catch (Exception e) {
            log.error("Failed to blacklist tokens for user: {}", e.getMessage());
        }
    }

    /**
     * Toggles a user's ban status (admin only)
     */
    @Transactional
    @CacheEvict(value = "users", allEntries = true)
    public GenericResponse toggleUserBan(UUID userId) {
        log.info("Toggling ban status for user {}", userId);

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with id: " + userId));

        // Log current ban status before toggle
        log.info("Current ban status for user {}: {}", userId, user.isBanned());

        // Toggle ban status
        user.setBanned(!user.isBanned());

        // Log new ban status after toggle  
        log.info("New ban status for user {}: {}", userId, user.isBanned());

        User savedUser = userRepository.save(user);

        // Verify saved state
        log.info("Saved user ban status for {}: {}", userId, savedUser.isBanned());

        // Clear all caches for this specific user
        String usernameKey = "username_" + savedUser.getUsername();
        String emailKey = "email_" + savedUser.getEmail();
        String userIdKey = savedUser.getId().toString();

        // Forcibly clear specific cache entries
        cacheEvict("users", usernameKey);
        cacheEvict("users", emailKey);
        cacheEvict("users", userIdKey);
        cacheEvict("users", "exists_username_" + savedUser.getUsername());

        String message = user.isBanned() ? "User banned successfully" : "User unbanned successfully";
        log.info("Successfully toggled ban status for user {}. New status: {}", userId, user.isBanned());

        return GenericResponse.builder()
                .status(200)
                .message(message)
                .timestamp(LocalDateTime.now())
                .success(true)
                .build();
    }

    /**
     * Finds a user by ID
     */
    @Transactional(readOnly = true)
    @Cacheable(value = "users", key = "#userId")
    public UserResponse findUserById(UUID userId) {
        log.info("Finding user with id: {}", userId);
        return userRepository.findById(userId)
                .map(DtoMapper::mapToUserResponse)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with id: " + userId));
    }

    /**
     * Finds a user by username
     */
    @Transactional(readOnly = true)
    @Cacheable(value = "users", key = "'username_' + #username")
    public UserResponse findUserByUsername(String username) {
        log.info("Finding user with username: {}", username);
        return userRepository.findByUsername(username)
                .map(DtoMapper::mapToUserResponse)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with username: " + username));
    }

    /**
     * Finds a user by email
     */
    @Transactional(readOnly = true)
    @Cacheable(value = "users", key = "'email_' + #email")
    public UserResponse findUserByEmail(String email) {
        log.info("Finding user with email: {}", email);
        return userRepository.findByEmail(email)
                .map(DtoMapper::mapToUserResponse)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with email: " + email));
    }

    /**
     * Checks if a username exists in the system
     */
    @Transactional(readOnly = true)
    @Cacheable(value = "users", key = "'exists_username_' + #username")
    public boolean existsByUsername(String username) {
        log.info("Checking if username exists: {}", username);
        return userRepository.existsByUsername(username);
    }

    /**
     * Finds a user by username
     */
    @Cacheable(value = "users", key = "#username")
    public User findByUsername(String username) {
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("User not found with username: " + username));
    }

    @Transactional
    @CacheEvict(value = "users", key = "#currentUsername")
    public UserResponse updateProfile(String currentUsername, ProfileUpdateRequest request) {
        try {
            User user = findByUsername(currentUsername);
            boolean usernameChanged = false;

            if (request.getUsername() != null && !request.getUsername().equals(currentUsername)) {
                if (userRepository.existsByUsername(request.getUsername())) {
                    throw new IllegalArgumentException("Username is already taken");
                }
                usernameChanged = true;
                user.setUsername(request.getUsername());
            }

            User savedUser = userRepository.save(user);
            log.info("Profile updated successfully for user: {}", currentUsername);

            // Handle cache invalidation if username changed
            if (usernameChanged) {
                log.info("Username changed from {} to {}. Invalidating caches.", currentUsername, savedUser.getUsername());

                // Invalidate all relevant caches
                cacheEvict("users", "username_" + savedUser.getUsername());
                cacheEvict("users", "exists_username_" + savedUser.getUsername());
                cacheEvict("users", savedUser.getUsername());

                // Update auth service to ensure JWT tokens reflect the new username
                log.info("Triggering username change handling in AuthService for user: {}", savedUser.getId());
                userDetailsService.handleUsernameChange(currentUsername, savedUser.getUsername(), savedUser.getId());
            }

            // Convert to UserResponse DTO and return it directly
            return DtoMapper.mapToUserResponse(savedUser);
        } catch (IllegalArgumentException e) {
            log.warn("Invalid profile update request: {}", e.getMessage());
            throw e;
        } catch (Exception e) {
            log.error("Error updating profile for user: {}", currentUsername, e);
            throw new RuntimeException("Failed to update profile", e);
        }
    }

    /**
     * Helper method to manually evict cache entries
     */
    public void cacheEvict(String cacheName, String cacheKey) {
        log.debug("Evicting cache entry: {} with key: {}", cacheName, cacheKey);
        if (cacheManager != null && cacheManager.getCache(cacheName) != null) {
            Objects.requireNonNull(cacheManager.getCache(cacheName)).evict(cacheKey);
        }
    }

    /**
     * Get a user by username
     *
     * @param username The username to look up
     * @return The user if found, null otherwise
     */
    public User getUserByUsername(String username) {
        if (username == null || username.isBlank()) {
            return null;
        }
        return userRepository.findByUsername(username).orElse(null);
    }

    /**
     * Check if a user ID belongs to the currently authenticated user
     *
     * @param userId The user ID to check
     * @return True if the user ID belongs to the current user
     */
    public boolean isCurrentUser(UUID userId) {
        if (userId == null) {
            return false;
        }

        // Get currently authenticated user
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            return false;
        }

        // Get principal from authentication
        Object principal = authentication.getPrincipal();
        UUID currentUserId = null;

        // Extract user ID based on principal type
        if (principal instanceof UserPrincipal userPrincipal) {
            currentUserId = userPrincipal.user().getId();
        } else if (principal instanceof UserDetails userDetails) {
            User user = getUserByUsername(userDetails.getUsername());
            if (user != null) {
                currentUserId = user.getId();
            }
        }

        return userId.equals(currentUserId);
    }
} 
