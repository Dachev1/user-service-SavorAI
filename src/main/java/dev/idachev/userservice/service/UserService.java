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
        validateNewUser(request);
        
        User user = createNewUser(request);
        User savedUser = userRepository.save(user);
        
        log.info("User registered: {}", savedUser.getEmail());
        
        try {
            // Use the enhanced EmailService with User object
            emailService.sendVerificationEmail(savedUser);
        } catch (Exception e) {
            // Log error but don't fail registration - email can be resent later
            log.error("Failed to send verification email during registration: {}", e.getMessage(), e);
        }
        
        return DtoMapper.mapToAuthResponse(savedUser, "");
    }

    /**
     * Verifies a user's email using the verification token
     *
     * @param token Verification token
     * @return True if verification successful
     */
    @Transactional
    public boolean verifyEmail(String token) {
        if (token == null || token.trim().isEmpty()) {
            log.warn("Verification failed: Token is null or empty");
            return false;
        }
        
        try {
            User user = userRepository.findByVerificationToken(token)
                    .orElseThrow(() -> new ResourceNotFoundException("Invalid verification token"));

            log.info("Found user with token: {}, current enabled status: {}", user.getEmail(), user.isEnabled());
            
            // Check if user is already verified
            if (user.isEnabled()) {
                log.info("User already verified: {}", user.getEmail());
                return true;
            }

            // Update user status
            user.setEnabled(true);
            user.setVerificationToken(null); 
            User savedUser = userRepository.save(user);
            
            // Force flush to ensure the transaction is committed
            userRepository.flush();
            
            log.info("Email verified for user: {}, new enabled status: {}", savedUser.getEmail(), savedUser.isEnabled());
            
            // Send welcome email after verification (non-blocking)
            try {
                emailService.sendWelcomeEmail(savedUser);
            } catch (Exception e) {
                // Log error but don't fail verification
                log.error("Failed to send welcome email after verification: {}", e.getMessage(), e);
            }
            
            return true;
        } catch (ResourceNotFoundException e) {
            log.warn("Verification failed: {}", e.getMessage());
            return false;
        } catch (Exception e) {
            log.error("Error verifying email with token: {}", token, e);
            return false;
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
        try {
            User user = userRepository.findByEmail(email)
                    .orElseThrow(() -> new ResourceNotFoundException("User not found with email: " + email));
            
            if (user.isEnabled()) {
                log.warn("Cannot resend verification email - user is already verified: {}", email);
                return false;
            }
            
            // If token is missing, generate a new one
            if (user.getVerificationToken() == null || user.getVerificationToken().isEmpty()) {
                user.setVerificationToken(emailService.generateVerificationToken());
                user = userRepository.save(user);
            }
            
            emailService.sendVerificationEmail(user);
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
        try {
            boolean verified = verifyEmail(token);

            if (verified) {
                return DtoMapper.mapToVerificationResponse(
                        null, true, "Your email has been verified successfully. You can now log in to your account.");
            } else {
                User existingUser = userRepository.findByVerificationToken(token).orElse(null);
                if (existingUser != null && existingUser.isEnabled()) {
                    return DtoMapper.mapToVerificationResponse(
                            null, true, "Your email was already verified. You can log in to your account.");
                } else {
                    return DtoMapper.mapToVerificationResponse(
                            null, false, "Verification failed. The link may be invalid or expired.");
                }
            }
        } catch (Exception e) {
            log.error("Unexpected error in email verification: {}", e.getMessage(), e);
            return DtoMapper.mapToVerificationResponse(
                    null, false, "An error occurred during verification. Please try again later.");
        }
    }

    // Private helper methods

    private void validateNewUser(RegisterRequest request) {
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
