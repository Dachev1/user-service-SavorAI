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
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

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
                         CacheManager cacheManager) {
        this.userRepository = userRepository;
        this.userDetailsService = userDetailsService;
        this.cacheManager = cacheManager;
    }

    /**
     * Gets the currently authenticated user
     */
    public User getCurrentUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || !authentication.isAuthenticated()) {
            throw new AuthenticationException("User not authenticated");
        }

        Object principal = authentication.getPrincipal();
        if ("anonymousUser".equals(principal)) {
            throw new AuthenticationException("User not authenticated");
        }

        if (!(principal instanceof UserPrincipal)) {
            throw new AuthenticationException("Invalid authentication principal type");
        }

        return ((UserPrincipal) principal).user();
    }

    /**
     * Gets current user information as a DTO
     */
    @Transactional(readOnly = true)
    public UserResponse getCurrentUserInfo() {
        User user = getCurrentUser();
        return DtoMapper.mapToUserResponse(user);
    }

    /**
     * Gets user information as a DTO, optionally by username or email
     */
    @Transactional(readOnly = true)
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
    @CacheEvict(value = "users", allEntries = true)
    public UserResponse updateProfile(String currentUsername, ProfileUpdateRequest request) {
        User user = findByUsername(currentUsername);
        boolean usernameChanged = false;

        if (request.getUsername() != null && !request.getUsername().isEmpty() && 
            !request.getUsername().equals(currentUsername)) {
            
            if (userRepository.existsByUsername(request.getUsername())) {
                throw new IllegalArgumentException("Username is already taken");
            }
            
            log.info("Username change requested from '{}' to '{}'", currentUsername, request.getUsername());
            usernameChanged = true;
            user.setUsername(request.getUsername());
        }

        User savedUser = userRepository.save(user);
        log.info("Profile updated successfully for user: {}", currentUsername);

        if (usernameChanged) {
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
} 