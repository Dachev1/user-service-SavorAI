package dev.idachev.userservice.service;

import dev.idachev.userservice.model.User;
import dev.idachev.userservice.repository.UserRepository;
import dev.idachev.userservice.security.UserPrincipal;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
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
public class UserDetailsService implements org.springframework.security.core.userdetails.UserDetailsService {

    private final UserRepository userRepository;
    private final CacheManager cacheManager;

    public UserDetailsService(UserRepository userRepository, CacheManager cacheManager) {
        this.userRepository = userRepository;
        this.cacheManager = cacheManager;
    }

    /**
     * Load a user by username or email
     */
    @Override
    @Transactional(readOnly = true)
    @Cacheable(value = "userDetails", key = "#usernameOrEmail", unless = "#result == null")
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
    @Cacheable(value = "userDetails", key = "'id_' + #userId", unless = "#result == null")
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

    @CacheEvict(value = "userDetails", key = "#username")
    public void clearUserDetailsCache(String username) {
        log.info("Clearing userDetails cache for username: {}", username);
    }

    @CacheEvict(value = "userDetails", key = "'id_' + #userId")
    public void clearUserDetailsCacheById(UUID userId) {
        log.info("Clearing userDetails cache for user ID: {}", userId);
    }

    /**
     * Handle a username change event with proper cache invalidation
     */
    public void handleUsernameChange(String oldUsername, String newUsername, UUID userId) {
        log.info("Handling username change: {} -> {}", oldUsername, newUsername);

        try {
            // Clear all relevant cache entries
            if (cacheManager != null) {
                // Clear entries from userDetails cache
                Cache userDetailsCache = cacheManager.getCache("userDetails");
                if (userDetailsCache != null) {
                    // Clear both usernames and user ID from userDetails cache
                    log.info("Clearing userDetails cache entries");
                    userDetailsCache.evict(oldUsername);
                    userDetailsCache.evict(newUsername);
                    userDetailsCache.evict("id_" + userId);
                }

                // Clear entries from users cache
                Cache usersCache = cacheManager.getCache("users");
                if (usersCache != null) {
                    // Clear all related keys from users cache
                    log.info("Clearing users cache entries");
                    String[] keysToEvict = {
                            oldUsername, newUsername,
                            "username_" + oldUsername, "username_" + newUsername,
                            "exists_username_" + oldUsername, "exists_username_" + newUsername,
                            userId.toString()
                    };

                    for (String key : keysToEvict) {
                        usersCache.evict(key);
                    }
                }
            } else {
                log.warn("CacheManager is null, skipping cache eviction");
            }

            // Force user to be logged out - set loggedIn to false
            userRepository.findById(userId).ifPresent(user -> {
                user.setLoggedIn(false);
                userRepository.save(user);
                log.info("Set user logged in status to false for user ID: {}", userId);
            });

            log.info("Username change cache eviction completed for user ID: {}", userId);
        } catch (Exception e) {
            log.error("Error during cache eviction for username change: {}", e.getMessage(), e);
        }
    }
} 
