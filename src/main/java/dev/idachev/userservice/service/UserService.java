package dev.idachev.userservice.service;

import dev.idachev.userservice.exception.ResourceNotFoundException;
import dev.idachev.userservice.mapper.DtoMapper;
import dev.idachev.userservice.mapper.EntityMapper;
import dev.idachev.userservice.model.Role;
import dev.idachev.userservice.model.User;
import dev.idachev.userservice.repository.UserRepository;
import dev.idachev.userservice.security.UserPrincipal;
import dev.idachev.userservice.web.dto.GenericResponse;
import dev.idachev.userservice.web.dto.ProfileUpdateRequest;
import dev.idachev.userservice.web.dto.RegisterRequest;
import dev.idachev.userservice.web.dto.UserResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
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
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final UserDetailsService userDetailsService;
    private final CacheManager cacheManager;
    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;
    private final TokenService tokenService;

    /**
     * Registers a new user
     */
    @Transactional
    public User registerUser(RegisterRequest request) {
        User newUser = EntityMapper.mapToNewUser(
                request,
                passwordEncoder,
                emailService.generateVerificationToken()
        );
        return userRepository.save(newUser);
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
     * Sets a user's role (admin only)
     */
    @Transactional
    @CacheEvict(value = "users", allEntries = true)
    public GenericResponse setUserRole(UUID userId, Role role) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with id: " + userId));

        user.setRole(role);
        user.setUpdatedOn(LocalDateTime.now());
        userRepository.saveAndFlush(user);

        return GenericResponse.builder()
                .status(200)
                .message("User role updated successfully")
                .timestamp(LocalDateTime.now())
                .success(true)
                .build();
    }

    /**
     * Updates a user's role and refreshes their token
     */
    @Transactional
    @CacheEvict(value = "users", allEntries = true)
    public GenericResponse updateUserRoleWithTokenRefresh(UUID userId, Role role) {
        // First update the role in the database
        GenericResponse roleUpdateResponse = setUserRole(userId, role);

        // If the database update was successful, refresh token
        if (roleUpdateResponse.isSuccess()) {
            try {
                tokenService.invalidateUserTokens(userId);
            } catch (Exception e) {
                roleUpdateResponse.setMessage(roleUpdateResponse.getMessage() +
                        " (Note: Token refresh failed, user will need to log out and back in)");
            }
        }

        return roleUpdateResponse;
    }

    /**
     * Toggles a user's ban status (admin only)
     */
    @Transactional
    @CacheEvict(value = "users", allEntries = true)
    public GenericResponse toggleUserBan(UUID userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with id: " + userId));

        // Toggle ban status
        user.setBanned(!user.isBanned());
        User savedUser = userRepository.save(user);

        // Clear specific cache entries
        cacheEvict("users", "username_" + savedUser.getUsername());
        cacheEvict("users", "email_" + savedUser.getEmail());
        cacheEvict("users", savedUser.getId().toString());
        cacheEvict("users", "exists_username_" + savedUser.getUsername());

        String message = user.isBanned() ? "User banned successfully" : "User unbanned successfully";

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
     * Finds a user by username
     */
    @Cacheable(value = "users", key = "#username")
    public User findByUsername(String username) {
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with username: " + username));
    }

    /**
     * Updates a user's profile
     */
    @Transactional
    @CacheEvict(value = "users", key = "#currentUsername")
    public UserResponse updateProfile(String currentUsername, ProfileUpdateRequest request) {
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

        // Handle cache invalidation if username changed
        if (usernameChanged) {
            cacheEvict("users", "username_" + savedUser.getUsername());
            cacheEvict("users", "exists_username_" + savedUser.getUsername());
            cacheEvict("users", savedUser.getUsername());

            userDetailsService.handleUsernameChange(currentUsername, savedUser.getUsername(), savedUser.getId());
        }

        return DtoMapper.mapToUserResponse(savedUser);
    }

    /**
     * Helper method to manually evict cache entries
     */
    public void cacheEvict(String cacheName, String cacheKey) {
        if (cacheManager != null && cacheManager.getCache(cacheName) != null) {
            Objects.requireNonNull(cacheManager.getCache(cacheName)).evict(cacheKey);
        }
    }

    /**
     * Get a user by username
     */
    public User getUserByUsername(String username) {
        if (username == null || username.isBlank()) {
            return null;
        }
        return userRepository.findByUsername(username).orElse(null);
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
            User user = getUserByUsername(userDetails.getUsername());
            if (user != null) {
                currentUserId = user.getId();
            }
        }

        return userId.equals(currentUserId);
    }

    /**
     * Checks if a username is available
     */
    public GenericResponse checkUsernameAvailability(String username) {
        boolean isAvailable = !existsByUsername(username);

        return GenericResponse.builder()
                .status(200)
                .message(isAvailable ? "Username is available" : "Username is already taken")
                .timestamp(LocalDateTime.now())
                .success(isAvailable)
                .build();
    }
} 
