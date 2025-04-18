package dev.idachev.userservice.service;

import java.util.Objects;
import java.util.UUID;

import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import dev.idachev.userservice.exception.InvalidRequestException;
import dev.idachev.userservice.exception.ResourceNotFoundException;
import dev.idachev.userservice.mapper.DtoMapper;
import dev.idachev.userservice.model.User;
import dev.idachev.userservice.repository.UserRepository;
import dev.idachev.userservice.web.dto.PasswordChangeRequest;
import dev.idachev.userservice.web.dto.UserResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Service responsible for user profile operations (viewing, password change,
 * deletion).
 * Username/profile updates are handled by UserService.
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class ProfileService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final CacheManager cacheManager;

    /**
     * Gets user information as a DTO by username.
     * Parameter 'username' is expected to be provided by the controller (e.g., from
     * path or principal).
     */
    @Transactional(readOnly = true)
    @Cacheable(value = "users", key = "'username_' + #username", unless = "#result == null")
    public UserResponse getUserInfoByUsername(String username) {
        if (username == null || username.isBlank()) {
            throw new InvalidRequestException("Username cannot be blank");
        }
        return DtoMapper.mapToUserResponse(findByUsername(username));
    }

    /**
     * Deletes the user account identified by username.
     * Requires username passed from controller (e.g., authenticated principal).
     */
    @Transactional
    public void deleteAccount(String username) {
        User user = findByUsername(username);
        UUID userId = user.getId();
        String email = user.getEmail();

        userRepository.delete(user);
        log.info("User account deleted: {}", username);

        evictUserCaches(userId, username, email);
    }

    /**
     * Changes the user's password.
     * Requires username passed from controller (e.g., authenticated principal).
     * TODO: Consider class-level validator for request DTO (passwords match).
     */
    @Transactional
    public void changePassword(String username, PasswordChangeRequest request) {
        User user = findByUsername(username);

        Objects.requireNonNull(request.getCurrentPassword(), "Current password cannot be null");
        Objects.requireNonNull(request.getNewPassword(), "New password cannot be null");
        Objects.requireNonNull(request.getConfirmPassword(), "Confirm password cannot be null");

        if (!passwordEncoder.matches(request.getCurrentPassword(), user.getPassword())) {
            throw new InvalidRequestException("Current password is incorrect");
        }

        if (!request.getNewPassword().equals(request.getConfirmPassword())) {
            throw new InvalidRequestException("New password and confirmation do not match");
        }

        user.changePassword(passwordEncoder.encode(request.getNewPassword()));
        User savedUser = userRepository.save(user);
        log.info("Password changed for user: {}", username);

        evictUserCaches(savedUser.getId(), savedUser.getUsername(), savedUser.getEmail());
    }

    /**
     * Finds a user entity by username.
     * Throws ResourceNotFoundException if not found.
     */
    private User findByUsername(String username) {
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with username: " + username));
    }

    /**
     * Helper method to evict common user-related cache entries.
     */
    private void evictUserCaches(UUID userId, String username, String email) {
        var usersCache = cacheManager.getCache("users");
        if (usersCache != null) {
            if (userId != null)
                usersCache.evict(userId);
            if (username != null)
                usersCache.evict("'username_'" + username);
            if (email != null)
                usersCache.evict("'email_'" + email);
            usersCache.evict("'allUsers'");
        }
        var usernamesCache = cacheManager.getCache("usernames");
        if (usernamesCache != null && userId != null) {
            usernamesCache.evict(userId);
        }
    }
}