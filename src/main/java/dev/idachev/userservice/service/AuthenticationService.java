package dev.idachev.userservice.service;

import dev.idachev.userservice.exception.AuthenticationException;
import dev.idachev.userservice.exception.DuplicateUserException;
import dev.idachev.userservice.exception.InvalidTokenException;
import dev.idachev.userservice.exception.ResourceNotFoundException;
import dev.idachev.userservice.exception.UserNotFoundException;
import dev.idachev.userservice.mapper.DtoMapper;
import dev.idachev.userservice.model.User;
import dev.idachev.userservice.repository.UserRepository;
import dev.idachev.userservice.security.UserPrincipal;
import dev.idachev.userservice.util.ResponseBuilder;
import dev.idachev.userservice.web.dto.AuthResponse;
import dev.idachev.userservice.web.dto.GenericResponse;
import dev.idachev.userservice.web.dto.RegisterRequest;
import dev.idachev.userservice.web.dto.SignInRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
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
import java.util.Optional;
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
    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;
    private final UserService userService;

    @Autowired
    public AuthenticationService(UserRepository userRepository,
                                AuthenticationManager authenticationManager,
                                TokenService tokenService,
                                PasswordEncoder passwordEncoder,
                                EmailService emailService,
                                UserService userService) {
        this.userRepository = userRepository;
        this.authenticationManager = authenticationManager;
        this.tokenService = tokenService;
        this.passwordEncoder = passwordEncoder;
        this.emailService = emailService;
        this.userService = userService;
    }

    /**
     * Registers a new user
     */
    @Transactional
    public AuthResponse register(RegisterRequest request) {
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new DuplicateUserException("Username already exists");
        }
        
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new DuplicateUserException("Email already exists");
        }

        User savedUser = userService.registerUser(request);
        emailService.sendVerificationEmailAsync(savedUser);
        
        // Generate token for the new user
        String token = tokenService.generateToken(new UserPrincipal(savedUser));
        
        // Return response with token
        return DtoMapper.mapToAuthResponse(
                savedUser,
                token
        );
    }

    /**
     * Authenticates a user
     */
    @Transactional
    public AuthResponse signIn(SignInRequest request) {
        User user = findUserByIdentifier(request.getIdentifier());

        if (!user.isEnabled()) {
            throw new AuthenticationException("Account not verified. Please check your email.");
        }

        if (user.isBanned()) {
            throw new AuthenticationException("Your account has been banned. Please contact support for assistance.");
        }

        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(user.getUsername(), request.getPassword()));
            
            UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();

            user.setLastLogin(LocalDateTime.now());
            user.setLoggedIn(true);
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
                .orElseThrow(() -> new dev.idachev.userservice.exception.UserNotFoundException("User not found with identifier: " + identifier));
    }

    /**
     * Logs out the user and blacklists their token
     */
    @Transactional
    public GenericResponse logout(String authHeader) {
        String token = extractTokenFromHeader(authHeader);
        
        if (token == null) {
            return ResponseBuilder.success("No active session found");
        }
        
        UUID userId = tokenService.extractUserId(token);
        tokenService.blacklistToken(token);
        
        if (userId != null) {
            userRepository.findById(userId).ifPresent(user -> {
                user.setLoggedIn(false);
                userRepository.save(user);
            });
        }
        
        return ResponseBuilder.success("Successfully logged out");
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

        if (tokenService.isTokenBlacklisted(token)) {
            throw new AuthenticationException("Token is blacklisted or has been logged out");
        }

        UUID userId;
        try {
            userId = tokenService.extractUserId(token);
            if (userId == null) {
                throw new InvalidTokenException("Invalid token: User ID not found");
            }
        } catch (Exception e) {
            throw new InvalidTokenException("Invalid token format", e);
        }
        
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new UserNotFoundException("User not found for token"));

        // Blacklist the old token for security
        tokenService.blacklistToken(token);

        String newToken = tokenService.generateToken(new UserPrincipal(user));
        
        return DtoMapper.mapToAuthResponse(user, newToken);
    }

    /**
     * Changes a user's username
     */
    @Transactional
    public GenericResponse changeUsername(String currentUsername, String newUsername, String password) {
        if (currentUsername == null || newUsername == null || password == null || 
            newUsername.isBlank() || password.isBlank()) {
            throw new IllegalArgumentException("Username and password are required");
        }
        
        if (!newUsername.matches("^[a-zA-Z0-9._-]{3,50}$")) {
            throw new IllegalArgumentException(
                "Username must be 3-50 characters and contain only letters, numbers, dots, underscores, and hyphens");
        }
        
        User user = userRepository.findByUsername(currentUsername)
                .orElseThrow(() -> new UserNotFoundException("User not found"));

        // Short-circuit if username unchanged
        if (currentUsername.equals(newUsername)) {
            return ResponseBuilder.success("Username unchanged");
        }
        
        if (!passwordEncoder.matches(password, user.getPassword())) {
            throw new AuthenticationException("Current password is incorrect");
        }

        if (userRepository.existsByUsername(newUsername)) {
            throw new DuplicateUserException("Username already exists");
        }

        user.setUsername(newUsername);
        user.setUpdatedOn(LocalDateTime.now());
        userRepository.save(user);
        
        tokenService.invalidateUserTokens(user.getId());

        return ResponseBuilder.success("Username updated successfully");
    }

    /**
     * Checks a user's ban status
     */
    public Map<String, Object> checkUserBanStatus(String identifier) {
        User user = findUserByIdentifier(identifier);

        Map<String, Object> response = new HashMap<>();
        response.put("username", user.getUsername());
        response.put("banned", user.isBanned());
        response.put("enabled", user.isEnabled());
        return response;
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