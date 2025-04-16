package dev.idachev.userservice.service;

import dev.idachev.userservice.exception.ResourceNotFoundException;
import dev.idachev.userservice.mapper.DtoMapper;
import dev.idachev.userservice.mapper.EntityMapper;
import dev.idachev.userservice.model.Role;
import dev.idachev.userservice.model.User;
import dev.idachev.userservice.repository.UserRepository;
import dev.idachev.userservice.security.UserPrincipal;
import dev.idachev.userservice.web.dto.BanStatusResponse;
import dev.idachev.userservice.web.dto.ProfileUpdateRequest;
import dev.idachev.userservice.web.dto.RegisterRequest;
import dev.idachev.userservice.web.dto.RoleUpdateResponse;
import dev.idachev.userservice.web.dto.UserResponse;
import dev.idachev.userservice.web.dto.UsernameAvailabilityResponse;
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
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Service for user management operations
 */
@Slf4j
@Service
public class UserService {

    private final UserRepository userRepository;
    private final UserDetailsService userDetailsService;
    private final CacheManager cacheManager;
    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;
    private final TokenService tokenService;

    public UserService(UserRepository userRepository,
                      UserDetailsService userDetailsService,
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
     * Updates a user's role and refreshes their token
     */
    @Transactional
    @CacheEvict(value = {"users", "usernames"}, allEntries = true)
    public RoleUpdateResponse updateUserRole(UUID userId, Role role) {
        if (isCurrentUser(userId)) {
            return RoleUpdateResponse.error("Admins cannot change their own role");
        }
        
        try {
            User user = userRepository.findById(userId)
                    .orElseThrow(() -> new ResourceNotFoundException("User not found with id: " + userId));

            user.setRole(role);
            user.setUpdatedOn(LocalDateTime.now());
            User savedUser = userRepository.saveAndFlush(user);
            
            boolean tokenRefreshed = true;
            try {
                tokenService.invalidateUserTokens(userId);
            } catch (Exception e) {
                log.error("Failed to refresh token for user {}: {}", userId, e.getMessage());
                tokenRefreshed = false;
            }
            
            return RoleUpdateResponse.success(
                savedUser.getId(),
                savedUser.getUsername(),
                savedUser.getRole(),
                tokenRefreshed
            );
        } catch (ResourceNotFoundException e) {
            return RoleUpdateResponse.error(e.getMessage());
        } catch (Exception e) {
            log.error("Error during role update: {}", e.getMessage(), e);
            return RoleUpdateResponse.error("Failed to update role: " + e.getMessage());
        }
    }

    /**
     * Toggles a user's ban status and invalidates their tokens if they are banned
     */
    @Transactional
    @CacheEvict(value = {"users", "usernames"}, allEntries = true)
    public BanStatusResponse toggleUserBan(UUID userId) {
        if (isCurrentUser(userId)) {
            return BanStatusResponse.error("Admins cannot ban themselves");
        }
        
        try {
            User user = userRepository.findById(userId)
                    .orElseThrow(() -> new ResourceNotFoundException("User not found with id: " + userId));
                    
            user.setBanned(!user.isBanned());
            User savedUser = userRepository.save(user);
            
            String message = user.isBanned() ? "User banned successfully" : "User unbanned successfully";
            
            if (user.isBanned()) {
                tokenService.invalidateUserTokens(userId);
            }
            
            return BanStatusResponse.success(
                savedUser.getId(), 
                savedUser.getUsername(), 
                savedUser.isBanned(),
                message
            );
        } catch (ResourceNotFoundException e) {
            return BanStatusResponse.error(e.getMessage());
        } catch (Exception e) {
            log.error("Error during ban operation: {}", e.getMessage(), e);
            return BanStatusResponse.error("Failed to process ban operation: " + e.getMessage());
        }
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
     * Updates a user's profile
     */
    @Transactional
    @CacheEvict(value = {"users", "usernames"}, allEntries = true)
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

        if (usernameChanged) {
            userDetailsService.handleUsernameChange(currentUsername, savedUser.getUsername(), savedUser.getId());
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
} 
