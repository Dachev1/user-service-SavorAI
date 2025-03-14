package dev.idachev.userservice.service;

import dev.idachev.userservice.config.JwtConfig;
import dev.idachev.userservice.exception.DuplicateUserException;
import dev.idachev.userservice.exception.ResourceNotFoundException;
import dev.idachev.userservice.mapper.DtoMapper;
import dev.idachev.userservice.model.User;
import dev.idachev.userservice.repository.UserRepository;
import dev.idachev.userservice.web.dto.AuthResponse;
import dev.idachev.userservice.web.dto.RegisterRequest;
import dev.idachev.userservice.web.dto.VerificationResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

/**
 * Service for user management operations
 */
@Service
@Slf4j
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;

    @Autowired
    public UserService(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            JwtConfig jwtConfig,
            EmailService emailService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.emailService = emailService;
    }

    /**
     * Registers a new user
     *
     * @param request Registration details
     * @return AuthResponse with registration status
     */
    @Transactional
    public AuthResponse register(RegisterRequest request) {
        // Validate request
        try {
            validateNewUser(request);
        } catch (Exception e) {
            log.warn("Registration validation failed: {}", e.getMessage());
            return DtoMapper.mapToAuthResponse(false, e.getMessage());
        }
        
        log.info("Registering new user with email: {}", request.getEmail());
        
        try {
            User newUser = createNewUser(request);
            User savedUser = userRepository.save(newUser);
            
            // Send verification email asynchronously
            emailService.sendVerificationEmailAsync(savedUser);
            
            log.info("User registered successfully: {}", savedUser.getEmail());
            
            return DtoMapper.mapToAuthResponse(
                    savedUser,
                    true,
                    "Registration successful! Please check your email to verify your account."
            );
        } catch (Exception e) {
            log.error("Error during user registration: {}", e.getMessage(), e);
            return DtoMapper.mapToAuthResponse(
                    false,
                    "Registration failed. Please try again later."
            );
        }
    }

    /**
     * Verifies email token
     *
     * @param token Token to verify
     * @return True if verified successfully
     * @throws ResourceNotFoundException If token is invalid or not found
     */
    @Transactional
    public boolean verifyEmail(String token) {
        if (token == null || token.trim().isEmpty()) {
            log.warn("Empty verification token");
            throw new ResourceNotFoundException("Verification token cannot be empty");
        }
        
        try {
            User savedUser = userRepository.findByVerificationToken(token)
                    .orElseThrow(() -> {
                        log.warn("No user found with verification token: {}", token);
                        return new ResourceNotFoundException("Invalid verification token");
                    });

            if (savedUser.isEnabled()) {
                log.info("User already verified: {}", savedUser.getEmail());
                return true;
            }

            savedUser.setEnabled(true);
            savedUser.setVerificationToken(null); // Clear token after use
            savedUser.setUpdatedOn(LocalDateTime.now());
            userRepository.save(savedUser);

            log.info("Email verified for user: {}, new enabled status: {}", savedUser.getEmail(), savedUser.isEnabled());
            
            return true;
        } catch (ResourceNotFoundException e) {
            // Re-throw ResourceNotFoundException for specific handling
            throw e;
        } catch (Exception e) {
            log.error("Error verifying email with token: {}", token, e);
            throw new RuntimeException("Email verification failed", e);
        }
    }

    /**
     * Resends verification email for a user
     *
     * @param email User's email address
     * @return True if email sent successfully
     */
    @Transactional
    public boolean resendVerificationEmail(String email) {
        if (email == null || email.trim().isEmpty()) {
            log.warn("Cannot resend verification to empty email");
            return false;
        }
        
        log.info("Attempting to resend verification email to: {}", email);
        
        try {
            User user = userRepository.findByEmail(email)
                    .orElseThrow(() -> {
                        log.warn("Cannot resend verification - user not found: {}", email);
                        return new ResourceNotFoundException("User not found with email: " + email);
                    });

            if (user.isEnabled()) {
                log.warn("Cannot resend verification email - user is already verified: {}", email);
                return false;
            }

            // If token is missing, generate a new one
            if (user.getVerificationToken() == null || user.getVerificationToken().isEmpty()) {
                log.info("Generating new verification token for user: {}", email);
                user.setVerificationToken(emailService.generateVerificationToken());
                user.setUpdatedOn(LocalDateTime.now());
                user = userRepository.save(user);
            }

            // Send verification email asynchronously
            emailService.sendVerificationEmailAsync(user);
            log.info("Verification email resent to: {}", email);

            return true;
        } catch (Exception e) {
            log.error("Failed to resend verification email to: {}", email, e);
            return false;
        }
    }

    /**
     * Verifies a user's email and returns detailed response
     *
     * @param token Verification token
     * @return Verification response with status
     */
    @Transactional
    public VerificationResponse verifyEmailAndGetResponse(String token) {
        if (token == null || token.trim().isEmpty()) {
            log.warn("Empty verification token in verifyEmailAndGetResponse");
            return DtoMapper.mapToVerificationResponse(
                    null, false, "Verification failed. The token is empty or invalid.");
        }
        
        try {
            log.info("Processing verification token with detailed response");
            boolean verified = verifyEmail(token);

            return DtoMapper.mapToVerificationResponse(
                    null, true, "Your email has been verified successfully. You can now log in to your account.");
                
        } catch (ResourceNotFoundException e) {
            log.warn("Resource not found in verification: {}", e.getMessage());
            
            // Check if user is already verified
            try {
                User existingUser = userRepository.findByEmail(
                        userRepository.findByVerificationToken(token)
                                .orElseThrow(() -> new ResourceNotFoundException("User not found"))
                                .getEmail())
                        .orElseThrow(() -> new ResourceNotFoundException("User not found"));
                        
                if (existingUser.isEnabled()) {
                    return DtoMapper.mapToVerificationResponse(
                            null, true, "Your email was already verified. You can log in to your account.");
                }
            } catch (Exception ignored) {
                // Do nothing, fall through to the failure response
            }
            
            return DtoMapper.mapToVerificationResponse(
                    null, false, "Verification failed. " + e.getMessage());
        } catch (Exception e) {
            log.error("Unexpected error in email verification: {}", e.getMessage(), e);
            return DtoMapper.mapToVerificationResponse(
                    null, false, "An error occurred during verification. Please try again later.");
        }
    }

    // Private helper methods

    private void validateNewUser(RegisterRequest request) {
        if (request == null) {
            throw new IllegalArgumentException("Registration request cannot be null");
        }
        
        if (request.getUsername() == null || request.getUsername().trim().isEmpty()) {
            throw new IllegalArgumentException("Username cannot be empty");
        }
        
        if (request.getEmail() == null || request.getEmail().trim().isEmpty()) {
            throw new IllegalArgumentException("Email cannot be empty");
        }
        
        if (request.getPassword() == null || request.getPassword().trim().isEmpty()) {
            throw new IllegalArgumentException("Password cannot be empty");
        }
        
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new DuplicateUserException("Username already exists");
        }

        if (userRepository.existsByEmail(request.getEmail())) {
            throw new DuplicateUserException("Email already exists");
        }
    }

    private User createNewUser(RegisterRequest request) {
        LocalDateTime now = LocalDateTime.now();
        String verificationToken = emailService.generateVerificationToken();

        return User.builder()
                .username(request.getUsername())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .verificationToken(verificationToken)
                .enabled(false)
                .createdOn(now)
                .updatedOn(now)
                .build();
    }
} 
