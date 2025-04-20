package dev.idachev.userservice.service;

import dev.idachev.userservice.config.EmailProperties;
import dev.idachev.userservice.exception.ResourceNotFoundException;
import dev.idachev.userservice.exception.VerificationException;
import dev.idachev.userservice.web.mapper.DtoMapper;
import dev.idachev.userservice.model.User;
import dev.idachev.userservice.repository.UserRepository;
import dev.idachev.userservice.security.UserPrincipal;
import dev.idachev.userservice.web.dto.AuthResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

/**
 * Service responsible for email verification operations
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class VerificationService {

    private final UserRepository userRepository;
    private final EmailService emailService;
    private final TokenService tokenService;
    private final EmailProperties emailProperties;

    /**
     * Generates a new random verification token.
     */
    public String generateVerificationToken() {
        return UUID.randomUUID().toString();
    }

    /**
     * Gets verification status for a user.
     * Returns AuthResponse containing user details and a JWT if verified.
     */
    @Transactional(readOnly = true)
    public AuthResponse getVerificationStatus(String identifier) {
        User user = findUserByEmail(identifier);
        String token = "";

        if (user.isEnabled()) {
            UserPrincipal userPrincipal = new UserPrincipal(user);
            token = tokenService.generateToken(userPrincipal);
            log.debug("User {} is verified, generated token for status check.", identifier);
        } else {
            log.debug("User {} is not verified.", identifier);
        }

        return DtoMapper.mapToAuthResponse(user, token);
    }

    /**
     * Verifies an email using the provided token.
     * Enables the user account and clears the verification token upon success.
     * Returns void.
     * Throws VerificationException if token is invalid, blank, or user already verified.
     * Throws ResourceNotFoundException if token does not match any user.
     */
    @Transactional
    public void verifyEmail(String token) {
        if (token == null || token.isBlank()) {
            throw new VerificationException("Verification token cannot be blank");
        }

        log.debug("Attempting to verify email with token: {}", token);
        User user = userRepository.findByVerificationToken(token)
                .orElseThrow(() -> {
                    log.warn("Invalid verification token used: {}", token);
                    return new ResourceNotFoundException("Invalid or expired verification token.");
                });

        if (user.isEnabled()) {
            log.warn("Attempted to verify already verified user: {}", user.getEmail());
            throw new VerificationException("Account is already verified.");
        }

        user.enableAccount();
        userRepository.save(user);

        log.info("Email verified successfully for user: {}", user.getEmail());
    }

    /**
     * Resends the verification email for a user identified by email.
     * Generates a new token if needed.
     * Returns void.
     * Throws VerificationException if the account is already verified.
     * Throws ResourceNotFoundException if the email does not match any user.
     * Propagates EmailSendException if sending fails.
     */
    @Transactional
    public void resendVerificationEmail(String email) {
        User user = findUserByEmail(email);

        if (user.isEnabled()) {
            log.warn("Cannot resend verification email - user is already verified: {}", email);
            throw new VerificationException("This account is already verified. You can sign in now.");
        }

        String token = user.getVerificationToken();
        if (token == null || token.isBlank()) {
            log.info("User {} had no verification token, generating a new one for resend.", email);
            token = generateVerificationToken();
            user.updateVerificationToken(token);
            user = userRepository.save(user);
        }

        String verificationUrl = buildVerificationUrl(token);

        emailService.sendVerificationEmail(user, verificationUrl);
        log.info("Verification email resent to: {}", email);
    }

    /**
     * Finds a user by email.
     * Throws ResourceNotFoundException if user not found.
     */
    private User findUserByEmail(String email) {
        return userRepository.findByEmail(email)
                .orElseThrow(() -> {
                    log.warn("User not found with email: {}", email);
                    return new ResourceNotFoundException("No account found with email: " + email);
                });
    }

    /**
     * Builds the full verification URL.
     * Public to be callable from other services (e.g., AuthenticationService).
     * TODO: Enhance with ServletUriComponentsBuilder if needed.
     */
    public String buildVerificationUrl(String token) {
        String baseUrl = emailProperties.getServiceBaseUrl();
        if (baseUrl.endsWith("/")) {
            baseUrl = baseUrl.substring(0, baseUrl.length() - 1);
        }
        return baseUrl + "/api/v1/verification/verify/" + token;
    }
} 