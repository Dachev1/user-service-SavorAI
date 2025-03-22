package dev.idachev.userservice.service;

import dev.idachev.userservice.exception.DuplicateUserException;
import dev.idachev.userservice.exception.ResourceNotFoundException;
import dev.idachev.userservice.mapper.DtoMapper;
import dev.idachev.userservice.mapper.EntityMapper;
import dev.idachev.userservice.model.Role;
import dev.idachev.userservice.model.User;
import dev.idachev.userservice.repository.UserRepository;
import dev.idachev.userservice.web.dto.AuthResponse;
import dev.idachev.userservice.web.dto.EmailVerificationResponse;
import dev.idachev.userservice.web.dto.GenericResponse;
import dev.idachev.userservice.web.dto.RegisterRequest;
import dev.idachev.userservice.web.dto.UserResponse;
import dev.idachev.userservice.web.dto.VerificationResponse;
import dev.idachev.userservice.web.dto.VerificationResult;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;


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
        // Check if request is null
        if (request == null) {
            log.error("Registration failed: request is null");
            return DtoMapper.mapToAuthResponse(false, "Registration request cannot be null");
        }
        
        log.info("Registering new user with email: {}", request.getEmail());

        try {
            // Check for existing username/email
            checkForExistingUser(request.getUsername(), request.getEmail());
            
            // Create and save new user
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
        } catch (DuplicateUserException e) {
            log.warn("Registration failed - duplicate user: {}", e.getMessage());
            return DtoMapper.mapToAuthResponse(false, e.getMessage());
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
        return Optional.ofNullable(token)
                .filter(t -> !t.trim().isEmpty())
                .flatMap(userRepository::findByVerificationToken)
                .map(user -> {
                    if (user.isEnabled()) {
                        log.info("User already verified: {}", user.getEmail());
                        return true;
                    }

                    user.setEnabled(true);
                    user.setVerificationToken(null); // Clear token after use
                    user.setUpdatedOn(LocalDateTime.now());
                    userRepository.save(user);

                    log.info("Email verified for user: {}, new enabled status: {}",
                            user.getEmail(), user.isEnabled());
                    return true;
                })
                .orElseThrow(() -> {
                    log.warn("No user found with verification token: {}", token);
                    return new ResourceNotFoundException("Invalid verification token");
                });
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
            verifyEmail(token);
            return DtoMapper.mapToVerificationResponse(
                    null, true, "Your email has been verified successfully. You can now log in to your account.");
                    
        } catch (ResourceNotFoundException e) {
            log.warn("Resource not found in verification: {}", e.getMessage());
            return handleVerificationNotFound(token, e);
            
        } catch (Exception e) {
            log.error("Unexpected error in email verification: {}", e.getMessage(), e);
            return DtoMapper.mapToVerificationResponse(
                    null, false, "An error occurred during verification. Please try again later.");
        }
    }
    
    /**
     * Handles the case when a verification token is not found
     * Checks if the user might already be verified
     */
    private VerificationResponse handleVerificationNotFound(String token, ResourceNotFoundException e) {
        try {
            return userRepository.findByVerificationToken(token)
                    .flatMap(u -> userRepository.findByEmail(u.getEmail()))
                    .filter(User::isEnabled)
                    .map(u -> DtoMapper.mapToVerificationResponse(
                            null, true, "Your email was already verified. You can log in to your account."))
                    .orElse(DtoMapper.mapToVerificationResponse(
                            null, false, "Verification failed. " + e.getMessage()));
        } catch (Exception ignored) {
            return DtoMapper.mapToVerificationResponse(
                    null, false, "Verification failed. " + e.getMessage());
        }
    }

    /**
     * Gets all users in the system (admin only)
     *
     * @return List of UserResponse DTOs
     */
    @Transactional(readOnly = true)
    public List<UserResponse> getAllUsers() {
        log.info("Admin request to get all users");
        
        return userRepository.findAll().stream()
                .map(DtoMapper::mapToUserResponse)
                .collect(Collectors.toList());
    }
    
    /**
     * Sets a user's role (admin only)
     *
     * @param userId User ID
     * @param role Role to set
     * @return GenericResponse with status
     * @throws ResourceNotFoundException if user not found
     */
    @Transactional
    public GenericResponse setUserRole(UUID userId, Role role) {
        log.info("Admin request to set user {} role to {}", userId, role);
        
        User user = userRepository.findById(userId)
                .orElseThrow(() -> {
                    log.warn("User not found with id: {}", userId);
                    return new ResourceNotFoundException("User not found with id: " + userId);
                });
        
        user.setRole(role);
        userRepository.save(user);
        
        log.info("User {} role updated to {}", userId, role);
        
        return DtoMapper.mapToGenericResponse(
                200,
                "User role updated successfully"
        );
    }

    /**
     * Resends verification email and returns a formatted response
     *
     * @param email User's email address
     * @return EmailVerificationResponse with status and message
     */
    @Transactional
    public EmailVerificationResponse resendVerificationEmailWithResponse(String email) {
        boolean sent = resendVerificationEmail(email);
        
        return new EmailVerificationResponse(
            sent,
            sent ? "Verification email has been resent. Please check your inbox."
                 : "Failed to resend verification email. Please try again later.",
            LocalDateTime.now()
        );
    }

    /**
     * Verifies email token and returns a result object suitable for redirect flow
     * This method does not throw exceptions
     *
     * @param token Token to verify
     * @return VerificationResult with success flag and error type if applicable
     */
    @Transactional
    public VerificationResult verifyEmailForRedirect(String token) {
        try {
            if (token == null || token.trim().isEmpty()) {
                log.warn("Empty verification token in verifyEmailForRedirect");
                return VerificationResult.failure("InvalidTokenException");
            }

            boolean verified = verifyEmail(token);
            return VerificationResult.success();
        } catch (ResourceNotFoundException e) {
            log.warn("Resource not found in verifyEmailForRedirect: {}", e.getMessage());
            return VerificationResult.failure("ResourceNotFoundException");
        } catch (Exception e) {
            log.error("Error in verifyEmailForRedirect: {}", e.getMessage(), e);
            return VerificationResult.failure(e.getClass().getSimpleName());
        }
    }

    // Private helper methods

    /**
     * Checks if a user with the same username or email already exists
     * 
     * @param username Username to check
     * @param email Email to check
     * @throws DuplicateUserException if user with same username or email exists
     */
    private void checkForExistingUser(String username, String email) {
        if (userRepository.existsByUsername(username)) {
            throw new DuplicateUserException("Username already exists");
        }

        if (userRepository.existsByEmail(email)) {
            throw new DuplicateUserException("Email already exists");
        }
    }

    /**
     * Creates a new user entity from registration request
     */
    private User createNewUser(RegisterRequest request) {
        String verificationToken = emailService.generateVerificationToken();
        return EntityMapper.mapToNewUser(request, passwordEncoder, verificationToken);
    }
} 
