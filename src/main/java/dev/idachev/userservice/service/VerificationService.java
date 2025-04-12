package dev.idachev.userservice.service;

import dev.idachev.userservice.exception.ResourceNotFoundException;
import dev.idachev.userservice.mapper.DtoMapper;
import dev.idachev.userservice.model.User;
import dev.idachev.userservice.repository.UserRepository;
import dev.idachev.userservice.security.UserPrincipal;
import dev.idachev.userservice.web.dto.AuthResponse;
import dev.idachev.userservice.web.dto.GenericResponse;
import dev.idachev.userservice.web.dto.VerificationResponse;
import dev.idachev.userservice.web.dto.VerificationResult;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Optional;

/**
 * Service responsible for email verification operations
 */
@Service
@Slf4j
public class VerificationService {

    private final UserRepository userRepository;
    private final EmailService emailService;
    private final TokenService tokenService;

    public VerificationService(UserRepository userRepository,
                               EmailService emailService,
                               TokenService tokenService) {
        this.userRepository = userRepository;
        this.emailService = emailService;
        this.tokenService = tokenService;
    }

    /**
     * Gets verification status for a user
     */
    public AuthResponse getVerificationStatus(String identifier) {
        User user = findUserByEmail(identifier);
        String token = "";

        if (user.isEnabled()) {
            UserPrincipal userPrincipal = new UserPrincipal(user);
            token = tokenService.generateToken(userPrincipal);
        }

        return DtoMapper.mapToAuthResponse(user, token);
    }

    /**
     * Verifies email token
     */
    @Transactional
    public boolean verifyEmail(String token) {
        return Optional.ofNullable(token)
                .flatMap(userRepository::findByVerificationToken)
                .map(user -> {
                    if (user.isEnabled()) {
                        log.info("User already verified: {}", user.getEmail());
                        return true;
                    }

                    user.setEnabled(true);
                    user.setVerificationToken(null);
                    user.setUpdatedOn(LocalDateTime.now());
                    userRepository.save(user);

                    log.info("Email verified for user: {}", user.getEmail());
                    return true;
                })
                .orElseThrow(() -> {
                    log.warn("No user found with verification token: {}", token);
                    return new ResourceNotFoundException("Invalid verification token");
                });
    }

    /**
     * Verifies a user's email and returns detailed response
     */
    @Transactional
    public VerificationResponse verifyEmailAndGetResponse(String token) {
        // Verify the email - this will throw ResourceNotFoundException if token is invalid
        verifyEmail(token);

        // Return successful response
        return DtoMapper.mapToVerificationResponse(
                null, true, "Your email has been verified successfully. You can now sign in to your account.");
    }

    /**
     * Resends verification email for a user
     */
    @Transactional
    public GenericResponse resendVerificationEmail(String email) {
        boolean sent = resendVerificationEmailInternal(email);
        return GenericResponse.builder()
                .status(200)
                .message(sent ? "Verification email has been resent. Please check your inbox."
                        : "Failed to resend verification email. Please try again later.")
                .timestamp(LocalDateTime.now())
                .success(sent)
                .build();
    }

    private boolean resendVerificationEmailInternal(String email) {
        User user = findUserByEmail(email);

        if (user.isEnabled()) {
            log.warn("Cannot resend verification email - user is already verified: {}", email);
            return false;
        }

        if (user.getVerificationToken() == null || user.getVerificationToken().isEmpty()) {
            user.setVerificationToken(emailService.generateVerificationToken());
            user.setUpdatedOn(LocalDateTime.now());
            user = userRepository.save(user);
        }

        emailService.sendVerificationEmailAsync(user);
        log.info("Verification email resent to: {}", email);

        return true;
    }

    /**
     * Verifies email token and returns a result object suitable for redirect flow
     */
    @Transactional
    public VerificationResult verifyEmailForRedirect(String token) {
        try {
            verifyEmail(token);
            return VerificationResult.success();
        } catch (ResourceNotFoundException e) {
            return VerificationResult.failure("ResourceNotFoundException");
        } catch (Exception e) {
            log.error("Error in verifyEmailForRedirect: {}", e.getMessage(), e);
            return VerificationResult.failure(e.getClass().getSimpleName());
        }
    }

    /**
     * Find user by email
     */
    private User findUserByEmail(String email) {
        return userRepository.findByEmail(email)
                .orElseThrow(() -> {
                    log.warn("User not found with email: {}", email);
                    return new ResourceNotFoundException("User not found with email: " + email);
                });
    }
} 