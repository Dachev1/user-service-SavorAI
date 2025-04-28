package dev.idachev.userservice.service;

import dev.idachev.userservice.model.User;
import dev.idachev.userservice.repository.UserRepository;
import dev.idachev.userservice.security.UserPrincipal;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

/**
 * Implementation of Spring Security's UserDetailsService
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class UserDetailsService implements org.springframework.security.core.userdetails.UserDetailsService {

    private final UserRepository userRepository;
    private final TokenService tokenService;

    /**
     * Load a user by username or email
     */
    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String usernameOrEmail) throws UsernameNotFoundException {
        if (usernameOrEmail == null || usernameOrEmail.trim().isEmpty()) {
            log.warn("Attempted to load user with null or empty username/email");
            throw new UsernameNotFoundException("Username/email cannot be null or empty");
        }

        log.debug("Loading user by identifier: {}", usernameOrEmail);

        User user = userRepository.findByUsername(usernameOrEmail)
                .or(() -> userRepository.findByEmail(usernameOrEmail))
                .orElseThrow(() -> {
                    log.warn("User not found with identifier: {}", usernameOrEmail);
                    return new UsernameNotFoundException("User not found with identifier: " + usernameOrEmail);
                });

        // Additional validation checks
        if (!user.isEnabled() && user.isBanned()) {
            log.warn("User '{}' is disabled and banned", usernameOrEmail);
        } else if (!user.isEnabled()) {
            log.warn("User '{}' is disabled", usernameOrEmail);
        } else if (user.isBanned()) {
            log.warn("User '{}' is banned", usernameOrEmail);
        }

        return new UserPrincipal(user);
    }

    /**
     * Load a user by their unique ID
     */
    @Transactional(readOnly = true)
    public UserDetails loadUserById(UUID userId) throws UsernameNotFoundException {
        if (userId == null) {
            log.warn("Attempted to load user with null ID");
            throw new UsernameNotFoundException("User ID cannot be null");
        }

        log.debug("Loading user by ID: {}", userId);

        User user = userRepository.findById(userId)
                .orElseThrow(() -> {
                    log.warn("User not found with ID: {}", userId);
                    return new UsernameNotFoundException("User not found with ID: " + userId);
                });

        // Additional validation checks
        if (!user.isEnabled() && user.isBanned()) {
            log.warn("User with ID {} is disabled and banned", userId);
        } else if (!user.isEnabled()) {
            log.warn("User with ID {} is disabled", userId);
        } else if (user.isBanned()) {
            log.warn("User with ID {} is banned", userId);
        }

        return new UserPrincipal(user);
    }

    public void clearUserDetailsCacheByUsername(String username) {
        log.debug("Cache eviction not needed - caching disabled");
    }

    public void clearUserDetailsCacheById(UUID userId) {
        log.debug("Cache eviction not needed - caching disabled");
    }

    /**
     * Handle a username change event with proper cache invalidation
     */
    @Transactional
    public void handleUsernameChange(String oldUsername, String newUsername, UUID userId) {
        log.info("Handling post-username-change actions for user ID: {} ({} -> {})", userId, oldUsername, newUsername);

        // Option 1: Force re-login by invalidating all existing tokens for the user
        try {
            tokenService.invalidateUserTokens(userId);
            log.info("Invalidated tokens for user ID: {} due to username change.", userId);
        } catch (Exception e) {
            log.error("Failed to invalidate tokens for user ID {} after username change: {}", userId, e.getMessage(), e);
        }

        log.info("Username change handling complete for user ID: {}", userId);
    }
} 
