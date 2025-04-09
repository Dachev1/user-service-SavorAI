package dev.idachev.userservice.service;

import dev.idachev.userservice.exception.AuthenticationException;
import dev.idachev.userservice.exception.ResourceNotFoundException;
import dev.idachev.userservice.mapper.DtoMapper;
import dev.idachev.userservice.model.User;
import dev.idachev.userservice.repository.UserRepository;
import dev.idachev.userservice.security.UserPrincipal;
import dev.idachev.userservice.web.dto.ProfileUpdateRequest;
import dev.idachev.userservice.web.dto.UserResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.CacheManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Objects;
import java.util.Optional;

/**
 * Service responsible for user profile operations
 */
@Service
@Slf4j
public class ProfileService {

    private final UserRepository userRepository;
    private final UserDetailsService userDetailsService;
    private final CacheManager cacheManager;

    @Autowired
    public ProfileService(UserRepository userRepository,
                          UserDetailsService userDetailsService,
                          CacheManager cacheManager){
        this.userRepository = userRepository;
        this.userDetailsService = userDetailsService;
        this.cacheManager = cacheManager;
    }

    /**
     * Gets the currently authenticated user
     */
    public User getCurrentUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (!isAuthenticatedUser(authentication)) {
            throw new AuthenticationException("User not authenticated");
        }

        UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();
        return userPrincipal.user();
    }

    /**
     * Gets current user information as a DTO
     */
    public UserResponse getCurrentUserInfo() {
        User user = getCurrentUser();
        return DtoMapper.mapToUserResponse(user);
    }

    /**
     * Gets user information as a DTO, optionally by username or email
     */
    public UserResponse getUserInfo(String identifier) {
        if (identifier == null || identifier.isEmpty()) {
            return getCurrentUserInfo();
        }

        User user = findByUsername(identifier);
        return DtoMapper.mapToUserResponse(user);
    }

    /**
     * Updates a user's profile
     */
    @Transactional
    public UserResponse updateProfile(String currentUsername, ProfileUpdateRequest request) {
        User user = findByUsername(currentUsername);
        boolean usernameChanged = false;

        // Handle username change if requested
        if (request.getUsername() != null && !request.getUsername().isEmpty() && !request.getUsername().equals(currentUsername)) {
            if (userRepository.existsByUsername(request.getUsername())) {
                throw new IllegalArgumentException("Username is already taken");
            }
            log.info("Username change requested from '{}' to '{}'", currentUsername, request.getUsername());
            usernameChanged = true;
            user.setUsername(request.getUsername());
        }

        // Avatar handling code removed

        User savedUser = userRepository.save(user);
        log.info("Profile updated successfully for user: {}", currentUsername);

        // Handle cache invalidation if username changed
        if (usernameChanged) {
            log.info("Username changed from {} to {}. Invalidating caches.", currentUsername, savedUser.getUsername());

            // Invalidate all relevant caches
            evictCacheEntries(
                    "username_" + savedUser.getUsername(),
                    "exists_username_" + savedUser.getUsername(),
                    savedUser.getUsername());

            // Update auth service to ensure JWT tokens reflect the new username
            userDetailsService.handleUsernameChange(currentUsername, savedUser.getUsername(), savedUser.getId());
        }

        return DtoMapper.mapToUserResponse(savedUser);
    }

    /**
     * Find user by username
     */
    private User findByUsername(String username) {
        return userRepository.findByUsername(username)
                .orElseThrow(() -> {
                    log.warn("User not found with username: {}", username);
                    return new ResourceNotFoundException("User not found with username: " + username);
                });
    }

    /**
     * Check if user is authenticated
     */
    private boolean isAuthenticatedUser(Authentication authentication) {
        return Optional.ofNullable(authentication)
                .filter(Authentication::isAuthenticated)
                .map(Authentication::getPrincipal)
                .filter(principal -> principal instanceof UserPrincipal)
                .isPresent();
    }

    /**
     * Helper method to evict cache entries
     */
    private void evictCacheEntries(String... keys) {
        if (cacheManager != null && cacheManager.getCache("users") != null) {
            for (String key : keys) {
                log.debug("Evicting cache entry: {} with key: {}", "users", key);
                Objects.requireNonNull(cacheManager.getCache("users")).evict(key);
            }
        }
    }
} 