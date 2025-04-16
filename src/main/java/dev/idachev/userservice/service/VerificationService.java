package dev.idachev.userservice.service;

import dev.idachev.userservice.exception.ResourceNotFoundException;
import dev.idachev.userservice.exception.VerificationException;
import dev.idachev.userservice.mapper.DtoMapper;
import dev.idachev.userservice.model.User;
import dev.idachev.userservice.repository.UserRepository;
import dev.idachev.userservice.security.UserPrincipal;
import dev.idachev.userservice.util.ResponseBuilder;
import dev.idachev.userservice.web.dto.AuthResponse;
import dev.idachev.userservice.web.dto.GenericResponse;
import dev.idachev.userservice.web.dto.VerificationResponse;
import dev.idachev.userservice.web.dto.VerificationResult;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.servlet.view.RedirectView;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
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

    @Autowired
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
    @Transactional(readOnly = true)
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
        if (token == null || token.isEmpty()) {
            throw new VerificationException("Verification token cannot be empty");
        }
        
        return Optional.of(token)
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
                    return new VerificationException("Invalid verification token");
                });
    }

    /**
     * Verifies a user's email and returns detailed response
     */
    @Transactional
    public VerificationResponse verifyEmailAndGetResponse(String token) {
        try {
            verifyEmail(token);
            return DtoMapper.mapToVerificationResponse(
                    null, true, "Your email has been verified successfully. You can now sign in to your account.");
        } catch (VerificationException e) {
            return DtoMapper.mapToVerificationResponse(null, false, e.getMessage());
        } catch (Exception e) {
            log.error("Unexpected error during verification: {}", e.getMessage(), e);
            return DtoMapper.mapToVerificationResponse(null, false, "Verification failed: " + e.getMessage());
        }
    }

    /**
     * Resends verification email for a user
     */
    @Transactional
    public GenericResponse resendVerificationEmail(String email) {
        User user = findUserByEmail(email);

        if (user.isEnabled()) {
            log.warn("Cannot resend verification email - user is already verified: {}", email);
            return ResponseBuilder.error("This account is already verified. You can sign in now.");
        }

        if (user.getVerificationToken() == null || user.getVerificationToken().isEmpty()) {
            user.setVerificationToken(emailService.generateVerificationToken());
            user.setUpdatedOn(LocalDateTime.now());
            user = userRepository.save(user);
        }

        emailService.sendVerificationEmailAsync(user);
        log.info("Verification email resent to: {}", email);

        return ResponseBuilder.success("Verification email has been resent. Please check your inbox.");
    }

    /**
     * Verifies email token and returns a result object suitable for redirect flow
     */
    @Transactional
    public VerificationResult verifyEmailForRedirect(String token) {
        try {
            verifyEmail(token);
            return VerificationResult.success();
        } catch (VerificationException e) {
            return VerificationResult.failure(e.getMessage());
        } catch (Exception e) {
            log.error("Error in verifyEmailForRedirect: {}", e.getMessage(), e);
            return VerificationResult.failure(e.getClass().getSimpleName());
        }
    }

    /**
     * Handles email verification redirect logic with error handling
     */
    public RedirectView handleEmailVerificationRedirect(String token, String redirectBaseUrl) {
        if (token == null || token.trim().isEmpty()) {
            String message = URLEncoder.encode("Invalid or missing verification token", StandardCharsets.UTF_8);
            return new RedirectView(redirectBaseUrl + "?verified=false&message=" + message);
        }

        try {
            VerificationResponse response = verifyEmailAndGetResponse(token);
            String message = URLEncoder.encode(response.getMessage(), StandardCharsets.UTF_8);
            return new RedirectView(
                    redirectBaseUrl + "?verified=" + response.isSuccess() + "&message=" + message);
        } catch (Exception e) {
            log.error("Error in email verification redirect handling: {}", e.getMessage(), e);
            String message = URLEncoder.encode("Verification failed: " + e.getMessage(), StandardCharsets.UTF_8);
            return new RedirectView(redirectBaseUrl + "?verified=false&message=" + message);
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