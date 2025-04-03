package dev.idachev.userservice.service;

import dev.idachev.userservice.model.User;
import dev.idachev.userservice.repository.UserRepository;
import dev.idachev.userservice.security.UserPrincipal;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Objects;
import java.util.UUID;

@Slf4j
@Service
public class UserDetailsService implements org.springframework.security.core.userdetails.UserDetailsService {

    private final UserRepository userRepository;
    private final CacheManager cacheManager;
    ;

    @Autowired
    public UserDetailsService(UserRepository userRepository, CacheManager cacheManager) {
        this.userRepository = userRepository;
        this.cacheManager = cacheManager;
    }

    @Override
    @Transactional(readOnly = true)
    @Cacheable(value = "userDetails", key = "#usernameOrEmail", unless = "#result == null")
    public UserDetails loadUserByUsername(String usernameOrEmail) throws UsernameNotFoundException {
        log.debug("Loading user by identifier: {}", usernameOrEmail);

        User user = userRepository.findByUsername(usernameOrEmail)
                .or(() -> userRepository.findByEmail(usernameOrEmail))
                .orElseThrow(() -> {
                    log.warn("User not found with identifier: {}", usernameOrEmail);
                    return new UsernameNotFoundException("User not found with identifier: " + usernameOrEmail);
                });

        return new UserPrincipal(user);
    }

    /**
     * Load a user by their unique ID
     */
    @Transactional(readOnly = true)
    @Cacheable(value = "userDetails", key = "'id_' + #userId", unless = "#result == null")
    public UserDetails loadUserById(UUID userId) throws UsernameNotFoundException {
        log.debug("Loading user by ID: {}", userId);

        User user = userRepository.findById(userId)
                .orElseThrow(() -> {
                    log.warn("User not found with ID: {}", userId);
                    return new UsernameNotFoundException("User not found with ID: " + userId);
                });

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
            // Clear all relevant cache entries in one operation for each cache
            if (cacheManager.getCache("userDetails") != null) {
                // Clear both usernames and user ID from userDetails cache
                log.info("Clearing userDetails cache entries");
                Objects.requireNonNull(cacheManager.getCache("userDetails")).evict(oldUsername);
                Objects.requireNonNull(cacheManager.getCache("userDetails")).evict(newUsername);
                Objects.requireNonNull(cacheManager.getCache("userDetails")).evict("id_" + userId);
            }

            if (cacheManager.getCache("users") != null) {
                // Clear all related keys from users cache
                log.info("Clearing users cache entries");
                String[] keysToEvict = {
                        oldUsername, newUsername,
                        "username_" + oldUsername, "username_" + newUsername,
                        "exists_username_" + oldUsername, "exists_username_" + newUsername,
                        userId.toString()
                };

                for (String key : keysToEvict) {
                    Objects.requireNonNull(cacheManager.getCache("users")).evict(key);
                }
            }

            // Force user to be logged out - set loggedIn to false
            userRepository.findById(userId).ifPresent(user -> {
                user.setLoggedIn(false);
                userRepository.save(user);
                log.info("Set user logged in status to false for user ID: {}", userId);
            });

            log.info("Username change cache eviction completed for user ID: {}", userId);
        } catch (Exception e) {
            log.error("Error during cache eviction for username change: {}", e.getMessage());
        }
    }
} 
