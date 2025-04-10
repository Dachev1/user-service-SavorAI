package dev.idachev.userservice.service;

import dev.idachev.userservice.exception.AuthenticationException;
import dev.idachev.userservice.exception.DuplicateUserException;
import dev.idachev.userservice.exception.ResourceNotFoundException;
import dev.idachev.userservice.mapper.DtoMapper;
import dev.idachev.userservice.model.User;
import dev.idachev.userservice.repository.UserRepository;
import dev.idachev.userservice.security.UserPrincipal;
import dev.idachev.userservice.web.dto.AuthResponse;
import dev.idachev.userservice.web.dto.GenericResponse;
import dev.idachev.userservice.web.dto.RegisterRequest;
import dev.idachev.userservice.web.dto.SignInRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Service responsible for user authentication operations
 */
@Service
@Slf4j
public class AuthenticationService {

    private final UserRepository userRepository;
    private final AuthenticationManager authenticationManager;
    private final TokenService tokenService;
    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;
    private final UserService userService;

    public AuthenticationService(
            UserRepository userRepository,
            AuthenticationManager authenticationManager,
            TokenService tokenService,
            UserDetailsService userDetailsService,
            PasswordEncoder passwordEncoder,
            EmailService emailService,
            UserService userService) {
        this.userRepository = userRepository;
        this.authenticationManager = authenticationManager;
        this.tokenService = tokenService;
        this.userDetailsService = userDetailsService;
        this.passwordEncoder = passwordEncoder;
        this.emailService = emailService;
        this.userService = userService;
    }

    /**
     * Registers a new user
     */
    @Transactional
    public AuthResponse register(RegisterRequest request) {
        log.info("Registering new user with email: {}", request.getEmail());

        // Check for existing user - let exceptions propagate to controller
        checkForExistingUser(request.getUsername(), request.getEmail());

        // Delegate user creation to the service
        User savedUser = userService.registerUser(request);

        // Send verification email asynchronously
        emailService.sendVerificationEmailAsync(savedUser);

        log.info("User registered successfully: {}", savedUser.getEmail());

        // Return success response
        return DtoMapper.mapToAuthResponse(
                savedUser,
                true,
                "Registration successful! Please check your email to verify your account."
        );
    }

    /**
     * Authenticates a user
     */
    @Transactional
    public AuthResponse signIn(SignInRequest request) {
        // Find the user by username or email
        User user = findByUsernameOrEmail(request.getIdentifier());

        // Check if account is verified
        if (!user.isEnabled()) {
            throw new AuthenticationException("Account not verified. Please check your email.");
        }

        // Check if the user is banned
        if (user.isBanned()) {
            log.warn("Banned user attempted to sign in: {}", user.getUsername());
            throw new AuthenticationException("Your account has been banned. Please contact support for assistance.");
        }

        // Authenticate with credentials - will throw BadCredentialsException for invalid password
        Authentication authentication = authenticate(request);
        UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();

        // Get fresh user data from database to ensure role is current
        user = userRepository.findById(userPrincipal.user().getId())
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        // Double check ban status after authentication
        if (user.isBanned()) {
            log.warn("Banned user authenticated but caught at final check: {}", user.getUsername());
            throw new AuthenticationException("Your account has been banned. Please contact support for assistance.");
        }

        // Update login status
        user.setLastLogin(LocalDateTime.now());
        user.setLoggedIn(true);
        userRepository.save(user);

        // Generate JWT token with current role
        String token = tokenService.generateToken(new UserPrincipal(user));

        log.info("User signed in: {} with role: {}", user.getEmail(), user.getRole());
        return DtoMapper.mapToAuthResponse(user, token);
    }

    /**
     * Logs out the current user and invalidates the token
     */
    @Transactional
    public void logout(UUID userId) {
        if (userId == null) {
            log.info("No user ID provided for logout");
            return;
        }

        log.info("Performing logout for user ID: {}", userId);
        userRepository.findById(userId)
                .ifPresentOrElse(
                        user -> {
                            user.setLoggedIn(false);
                            userRepository.save(user);
                            log.info("User status updated to logged out");
                        },
                        () -> log.warn("User not found for status update: {}", userId)
                );
    }

    /**
     * Logs out the user by JWT token, blacklists the token and updates user status
     */
    @Transactional
    public void logout(String token) {
        if (token == null || token.isBlank()) {
            log.info("No token provided for logout");
            return;
        }

        try {
            // Extract the user ID from the token
            UUID userId = tokenService.extractUserId(token);

            // Blacklist the token
            tokenService.blacklistToken("Bearer " + token);

            // Update user login status
            if (userId != null) {
                logout(userId);
            }
        } catch (Exception e) {
            log.warn("Error during token-based logout: {}", e.getMessage());
        }
    }

    /**
     * Refreshes a JWT token
     */
    @Transactional
    public AuthResponse refreshToken(String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw new AuthenticationException("Invalid or missing Authorization header");
        }

        String jwtToken = authHeader.substring(7);

        try {
            UUID userId = tokenService.extractUserId(jwtToken);

            // Force reload from database to get the latest data
            UserDetails userDetails = ((dev.idachev.userservice.service.UserDetailsService) userDetailsService)
                    .loadUserById(userId);
            User user = ((UserPrincipal) userDetails).user();

            // Blacklist the old token and generate a new one
            tokenService.blacklistToken(authHeader);
            String newToken = tokenService.generateToken(userDetails);

            log.info("Token refreshed successfully for user: {}", user.getEmail());
            return DtoMapper.mapToAuthResponse(user, newToken);
        } catch (Exception e) {
            log.error("Token refresh failed: {}", e.getMessage());
            throw new AuthenticationException("Token refresh failed", e);
        }
    }

    /**
     * Finds a user by username or email
     */
    public User findByUsernameOrEmail(String identifier) {
        log.debug("Looking up user by identifier: {}", identifier);

        return userRepository.findByUsername(identifier)
                .or(() -> userRepository.findByEmail(identifier))
                .orElseThrow(() -> {
                    log.warn("User not found with identifier: {}", identifier);
                    return new ResourceNotFoundException("User not found with username/email: " + identifier);
                });
    }

    /**
     * Authenticate user with username/password
     */
    private Authentication authenticate(SignInRequest request) {
        try {
            return authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.getIdentifier(),
                            request.getPassword()
                    )
            );
        } catch (Exception e) {
            log.error("Authentication failed: {}", e.getMessage());
            throw e;
        }
    }

    /**
     * Checks if a user exists with the given username or email
     */
    private void checkForExistingUser(String username, String email) {
        if (userRepository.existsByUsername(username)) {
            throw new DuplicateUserException("Username already taken: " + username);
        }
        if (userRepository.existsByEmail(email)) {
            throw new DuplicateUserException("Email already registered: " + email);
        }
    }

    /**
     * Changes the username for an authenticated user
     */
    @Transactional
    public GenericResponse changeUsername(String currentUsername, String newUsername, String password) {
        log.info("Changing username from {} to {}", currentUsername, newUsername);

        // Validate new username is not null
        if (newUsername == null || newUsername.trim().isEmpty()) {
            log.warn("Username change failed: new username is null or empty");
            throw new IllegalArgumentException("New username cannot be null or empty");
        }

        // Find the user
        User user = userRepository.findByUsername(currentUsername)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with username: " + currentUsername));

        // Verify the password
        if (!passwordEncoder.matches(password, user.getPassword())) {
            log.warn("Username change failed: incorrect password for user {}", currentUsername);
            throw new AuthenticationException("Password is incorrect");
        }

        // Check if new username is already taken
        if (userRepository.existsByUsername(newUsername)) {
            log.warn("Username change failed: username {} is already taken", newUsername);
            throw new DuplicateUserException("Username is already taken: " + newUsername);
        }

        // Store the old username for reference
        String oldUsername = user.getUsername();

        // Update username
        user.setUsername(newUsername);
        userRepository.save(user);

        // Update any tokens to reflect the new username
        ((dev.idachev.userservice.service.UserDetailsService) userDetailsService)
                .handleUsernameChange(oldUsername, newUsername, user.getId());

        // Force blacklist all tokens for this user
        blacklistUserTokens(user.getId());

        log.info("Username changed successfully from {} to {}", oldUsername, newUsername);

        return GenericResponse.builder()
                .success(true)
                .status(200)
                .message("Username changed successfully. Please sign in with your new username.")
                .timestamp(LocalDateTime.now())
                .build();
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
     * Get user ID by username
     */
    public UUID getUserIdByUsername(String username) {
        log.debug("Getting user ID for username: {}", username);

        return userRepository.findByUsername(username)
                .map(User::getId)
                .orElseThrow(() -> {
                    log.warn("User not found with username: {}", username);
                    return new ResourceNotFoundException("User not found with username: " + username);
                });
    }

    /**
     * Extract user ID from Authentication object
     * This method centralizes the user ID extraction logic that was previously in the controller
     * Returns null if authentication is null or user ID cannot be extracted
     */
    public UUID extractUserIdFromAuthentication(Authentication authentication) {
        if (authentication == null) {
            log.error("Authentication context is null");
            return null; // Return null instead of throwing exception
        }

        Object principal = authentication.getPrincipal();

        // Handle UserPrincipal case
        if (principal instanceof UserPrincipal userPrincipal) {
            return userPrincipal.user().getId();
        }

        // Handle UserDetails case
        if (principal instanceof org.springframework.security.core.userdetails.UserDetails userDetails) {
            try {
                String username = userDetails.getUsername();
                log.debug("Extracting user ID for username: {}", username);
                return getUserIdByUsername(username);
            } catch (Exception e) {
                log.error("Error extracting user ID from UserDetails", e);
                return null; // Return null instead of throwing exception
            }
        }

        // Handle String case (username)
        if (principal instanceof String username) {
            try {
                log.debug("Extracting user ID for username string: {}", username);
                return getUserIdByUsername(username);
            } catch (Exception e) {
                log.error("Error extracting user ID from username string", e);
                return null; // Return null instead of throwing exception
            }
        }

        log.error("Unable to extract user ID from authentication principal type: {}",
                principal != null ? principal.getClass().getName() : "null");
        return null; // Return null instead of throwing exception
    }

    /**
     * Extract user ID directly from JWT token
     * This allows logout even when full authentication isn't possible
     */
    public UUID extractUserIdFromToken(String token) {
        if (token == null || token.isEmpty()) {
            return null;
        }

        try {
            return tokenService.extractUserId(token);
        } catch (Exception e) {
            log.error("Error extracting user ID from token: {}", e.getMessage());
            return null;
        }
    }

    /**
     * Checks if a user is banned by their username or email.
     * Uses a safety pattern to prevent username enumeration attacks.
     * 
     * @param identifier The username or email to check
     * @return A map containing the ban status, always returns a result even if user doesn't exist
     */
    public Map<String, Object> checkUserBanStatus(String identifier) {
        log.info("Checking ban status for user identifier: {}", identifier);
        Map<String, Object> response = new HashMap<>();
        
        try {
            User user = findByUsernameOrEmail(identifier);
            response.put("banned", user.isBanned());
        } catch (ResourceNotFoundException e) {
            // Return banned:false for non-existent users
            // This is a security measure to prevent username enumeration attacks
            log.warn("User not found for ban status check: {}", identifier);
            response.put("banned", false);
        }
        
        return response;
    }
} 