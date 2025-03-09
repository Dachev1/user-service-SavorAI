package dev.idachev.userservice.service;

import dev.idachev.userservice.config.JwtConfig;
import dev.idachev.userservice.exception.DuplicateUserException;
import dev.idachev.userservice.mapper.DtoMapper;
import dev.idachev.userservice.model.User;
import dev.idachev.userservice.repository.UserRepository;
import dev.idachev.userservice.web.dto.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.UUID;

@Service
public class UserService {
    private static final Logger log = LoggerFactory.getLogger(UserService.class);

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtConfig jwtConfig;
    private final AuthenticationManager authenticationManager;
    private final EmailService emailService;

    @Autowired
    public UserService(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            JwtConfig jwtConfig,
            AuthenticationManager authenticationManager,
            EmailService emailService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtConfig = jwtConfig;
        this.authenticationManager = authenticationManager;
        this.emailService = emailService;
    }

    @Transactional
    public AuthResponse register(RegisterRequest request) {
        // Check if username or email already exists
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new DuplicateUserException("Username already exists");
        }
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new DuplicateUserException("Email already exists");
        }

        // Create new user using builder with manual defaults
        String verificationToken = UUID.randomUUID().toString();
        LocalDateTime now = LocalDateTime.now();
        
        User user = User.builder()
                .username(request.getUsername())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .verificationToken(verificationToken)
                .enabled(false)  // Explicitly set default
                .createdOn(now)  // Explicitly set default
                .updatedOn(now)  // Explicitly set default
                .build();

        // Save user
        User savedUser = userRepository.save(user);
        log.info("User registered: {}", savedUser.getEmail());

        // Send verification email
        emailService.sendVerificationEmail(savedUser.getEmail(), savedUser.getUsername(), verificationToken);

        // For security reasons, don't generate a token for unverified users
        return DtoMapper.mapToAuthResponse(savedUser, "");
    }

    /**
     * Authenticates a user and generates a JWT token
     *
     * @param request Login request containing email and password
     * @return AuthResponse with token and user information
     */
    @Transactional
    public AuthResponse login(LoginRequest request) {
        try {
            // Authenticate user with email
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword())
            );

            // Set authentication in security context
            SecurityContextHolder.getContext().setAuthentication(authentication);

            // Get authenticated user
            User user = (User) authentication.getPrincipal();

            // Check if email is verified
            if (!user.isEnabled()) {
                throw new RuntimeException("Account not verified. Please check your email for verification link.");
            }
            
            // Update last login timestamp
            user.updateLastLogin();
            userRepository.save(user);

            // Generate JWT token
            String token = jwtConfig.generateToken(user);
            log.info("User logged in: {}", user.getEmail());

            // Return response
            return DtoMapper.mapToAuthResponse(user, token);
        } catch (Exception e) {
            log.error("Login failed for user {}: {}", request.getEmail(), e.getMessage());
            throw e;
        }
    }

    @Transactional
    public boolean verifyEmail(String token) {
        try {
            User user = userRepository.findByVerificationToken(token)
                    .orElseThrow(() -> new RuntimeException("Invalid verification token"));

            user.setEnabled(true);
            user.setVerificationToken(null);
            userRepository.save(user);
            log.info("Email verified for user: {}", user.getEmail());

            return true;
        } catch (Exception e) {
            log.error("Error verifying email with token: {}", token, e);
            return false;
        }
    }

    @Transactional
    public VerificationResponse verifyEmailAndGetResponse(String token) {
        try {
            boolean verified = verifyEmail(token);
            User user = null;
            
            // Try to find the user by token if verification was successful
            if (verified) {
                user = userRepository.findByVerificationToken(token).orElse(null);
                return DtoMapper.mapToVerificationResponse(user, true, "Email verified successfully");
            } else {
                return DtoMapper.mapToVerificationResponse(null, false, "Verification failed");
            }
        } catch (Exception e) {
            return DtoMapper.mapToVerificationResponse(null, false, "Invalid verification token");
        }
    }

    public User getCurrentUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            throw new RuntimeException("User not authenticated");
        }
        return (User) authentication.getPrincipal();
    }

    /**
     * Checks if a user's email is verified
     * 
     * @param email The user's email address
     * @return AuthResponse with verification status and token if verified
     */
    public AuthResponse getVerificationStatus(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found with email: " + email));
        
        boolean isVerified = user.isEnabled();
        
        // Only generate a token if the user is verified
        String token = isVerified ? jwtConfig.generateToken(user) : "";
        
        return DtoMapper.mapToAuthResponse(user, token);
    }

    /**
     * Gets the currently authenticated user's information as a response object
     * 
     * @return UserResponse containing user information
     */
    public UserResponse getCurrentUserInfo() {
        User user = getCurrentUser();
        return DtoMapper.mapToUserResponse(user);
    }
    
    /**
     * Logs out the current user by clearing the security context
     * 
     * @return MessageResponse with success message
     */
    public MessageResponse logout() {
        SecurityContextHolder.clearContext();
        return DtoMapper.mapToMessageResponse(true, "Logged out successfully");
    }
} 
