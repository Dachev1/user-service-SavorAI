package dev.idachev.userservice.service;

import dev.idachev.userservice.exception.AccountVerificationException;
import dev.idachev.userservice.exception.AuthenticationException;
import dev.idachev.userservice.exception.DuplicateUserException;
import dev.idachev.userservice.exception.UserNotFoundException;
import dev.idachev.userservice.mapper.DtoMapper;
import dev.idachev.userservice.model.User;
import dev.idachev.userservice.repository.UserRepository;
import dev.idachev.userservice.security.UserPrincipal;
import dev.idachev.userservice.web.dto.AuthResponse;
import dev.idachev.userservice.web.dto.RegisterRequest;
import dev.idachev.userservice.web.dto.SignInRequest;
import dev.idachev.userservice.web.dto.UserStatusResponse;
import io.jsonwebtoken.JwtException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Date;
import java.util.Optional;
import java.util.UUID;

/**
 * Service responsible for user authentication operations
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class AuthenticationService {

    // Username validation regex constant
    private static final String USERNAME_REGEX = "^[a-zA-Z0-9._-]{3,50}$";

    private final UserRepository userRepository;
    private final AuthenticationManager authenticationManager;
    private final TokenService tokenService;
    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;
    private final UserService userService;
    private final VerificationService verificationService;

    /**
     * Registers a new user and initiates email verification.
     */
    @Transactional
    public AuthResponse register(RegisterRequest request) {
        if (userRepository.existsByUsername(request.username())) {
            throw new DuplicateUserException("Username already exists");
        }

        if (userRepository.existsByEmail(request.email())) {
            throw new DuplicateUserException("Email already exists");
        }

        User savedUser = userService.registerUser(request);

        String verificationToken = savedUser.getVerificationToken();
        String verificationUrl = verificationService.buildVerificationUrl(verificationToken);

        try {
            emailService.sendVerificationEmail(savedUser, verificationUrl);
        } catch (Exception e) {
            log.error("Failed to send verification email for user {}: {}",
                    savedUser.getEmail(), e.getMessage(), e);
        }

        String jwtToken = tokenService.generateToken(new UserPrincipal(savedUser));

        return DtoMapper.mapToAuthResponse(savedUser, jwtToken);
    }

    /**
     * Authenticates a user
     */
    @Transactional
    public AuthResponse signIn(SignInRequest request) {
        User user = findUserByIdentifier(request.identifier());

        if (!user.isEnabled()) {
            throw new AccountVerificationException("Account not verified. Please check your email.");
        }

        if (user.isBanned()) {
            throw new AuthenticationException("Your account has been banned. Please contact support for assistance.");
        }

        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(user.getUsername(), request.password()));

            UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();

            user.updateLastLogin();
            user.markAsLoggedIn();
            userRepository.save(user);

            String token = tokenService.generateToken(userPrincipal);
            return DtoMapper.mapToAuthResponse(user, token);
        } catch (BadCredentialsException e) {
            throw new AuthenticationException("Invalid credentials");
        }
    }

    /**
     * Find user by username or email
     */
    private User findUserByIdentifier(String identifier) {
        Optional<User> user = userRepository.findByUsername(identifier);
        if (user.isPresent()) {
            return user.get();
        }

        return userRepository.findByEmail(identifier)
                .orElseThrow(() -> new AuthenticationException("Invalid credentials"));
    }

    /**
     * Logs out the user and blacklists their token.
     * Throws AuthenticationException if token is invalid/missing.
     */
    @Transactional
    public void logout(String authHeader) {
        String token = extractTokenFromHeader(authHeader);

        if (token == null) {
            log.warn("Logout attempt with missing token.");
            throw new AuthenticationException("Logout requires a valid token.");
        }

        UUID userId = null;
        long expiryMillis = 0;
        try {
            userId = tokenService.extractUserId(token);
            Date expiryDate = tokenService.extractExpiration(token);
            expiryMillis = (expiryDate != null) ? expiryDate.getTime() : 0;
        } catch (JwtException e) {
            log.warn("Could not extract info from token during logout (possibly invalid/expired): {}", e.getMessage());
        } catch (Exception e) {
            log.error("Unexpected error extracting token info during logout: {}", e.getMessage(), e);
        }

        try {
            tokenService.blacklistToken(token);
        } catch (Exception e) {
            log.error("Failed to blacklist token {} during logout: {}", token, e.getMessage(), e);
        }

        if (userId != null) {
            userRepository.findById(userId).ifPresent(user -> {
                user.markAsLoggedOut();
                userRepository.save(user);
            });
        } else {
            log.warn("Could not determine userId from token during logout: {}", token);
        }
    }

    /**
     * Refreshes a JWT token
     */
    @Transactional
    public AuthResponse refreshToken(String authHeader) {
        String token = extractTokenFromHeader(authHeader);

        if (token == null) {
            throw new AuthenticationException("Invalid or missing Authorization header");
        }

        if (tokenService.isJwtBlacklisted(token)) {
            throw new AuthenticationException("Token is blacklisted or has been logged out");
        }

        UUID userId = tokenService.extractUserId(token);
        Date expiry = tokenService.extractExpiration(token);
        long expiryMillis = (expiry != null) ? expiry.getTime() : 0;

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new UserNotFoundException("User not found for token"));

        if (tokenService.isJwtBlacklisted(token) || tokenService.isUserInvalidated(userId)) {
            throw new AuthenticationException("Token has been invalidated");
        }

        tokenService.blacklistToken(token);

        String newToken = tokenService.generateToken(new UserPrincipal(user));

        return DtoMapper.mapToAuthResponse(user, newToken);
    }

    /**
     * Changes a user's username. Requires current password.
     * Invalidates user tokens.
     * Returns void.
     */
    @Transactional
    public void changeUsername(String currentUsername, String newUsername, String password) {
        if (currentUsername == null || newUsername == null || password == null ||
                newUsername.isBlank() || password.isBlank()) {
            throw new IllegalArgumentException("Current username, new username, and password are required");
        }

        if (!newUsername.matches(USERNAME_REGEX)) {
            throw new IllegalArgumentException(
                    "Username must be 3-50 characters and contain only letters, numbers, dots, underscores, and hyphens");
        }

        User user = userRepository.findByUsername(currentUsername)
                .orElseThrow(() -> new UserNotFoundException("User not found"));

        if (currentUsername.equals(newUsername)) {
            log.info("Username change requested for user {} but new username is the same.", currentUsername);
            return;
        }

        if (!passwordEncoder.matches(password, user.getPassword())) {
            throw new AuthenticationException("Current password is incorrect");
        }

        if (userRepository.existsByUsername(newUsername)) {
            throw new DuplicateUserException("Username already exists");
        }

        user.updateUsername(newUsername);
        userRepository.save(user);

        tokenService.invalidateUserTokens(user.getId());
        log.info("Username changed successfully for user ID: {}", user.getId());
    }

    /**
     * Checks a user's basic status (enabled, banned).
     * Returns a UserStatusResponse DTO.
     */
    @Transactional(readOnly = true)
    public UserStatusResponse checkUserStatus(String identifier) {
        User user = findUserByIdentifier(identifier);

        return UserStatusResponse.builder()
                .username(user.getUsername())
                .enabled(user.isEnabled())
                .banned(user.isBanned())
                .build();
    }

    /**
     * Extracts token from Authorization header
     */
    private String extractTokenFromHeader(String authHeader) {
        return authHeader != null && authHeader.startsWith("Bearer ")
                ? authHeader.substring(7)
                : null;
    }
} 