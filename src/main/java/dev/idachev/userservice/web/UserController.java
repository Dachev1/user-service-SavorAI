package dev.idachev.userservice.web;

import dev.idachev.userservice.service.AuthenticationService;
import dev.idachev.userservice.service.UserService;
import dev.idachev.userservice.web.dto.AuthResponse;
import dev.idachev.userservice.web.dto.ErrorResponse;
import dev.idachev.userservice.web.dto.LoginRequest;
import dev.idachev.userservice.web.dto.RegisterRequest;
import dev.idachev.userservice.web.dto.UserResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.Map;

/**
 * REST controller for user management operations
 */
@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/user")
public class UserController {

    private final UserService userService;
    private final AuthenticationService authenticationService;

    /**
     * Registers a new user
     * @param request User registration details
     * @return Auth response with JWT token and verification status
     */
    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@Valid @RequestBody RegisterRequest request) {
        log.info("Registration request received for email: {}", request.getEmail());
        return ResponseEntity.status(HttpStatus.CREATED).body(userService.register(request));
    }

    /**
     * Authenticates a user
     * @param request Login credentials
     * @return Auth response with JWT token
     */
    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest request) {
        log.info("Login request received for email: {}", request.getEmail());
        return ResponseEntity.ok(authenticationService.login(request));
    }

    /**
     * Retrieves current authenticated user information
     * @return Current user details
     */
    @GetMapping("/current-user")
    public ResponseEntity<UserResponse> getCurrentUser() {
        log.debug("Current user information requested");
        return ResponseEntity.ok(authenticationService.getCurrentUserInfo());
    }

    /**
     * Logs out current user
     * @return Success response
     */
    @PostMapping("/logout")
    public ResponseEntity<ErrorResponse> logout() {
        log.info("Logout request received");
        return ResponseEntity.ok(authenticationService.logout());
    }

    /**
     * Checks user verification status
     * @param email User email
     * @return Auth response with verification status
     */
    @GetMapping("/verification-status")
    public ResponseEntity<AuthResponse> getVerificationStatus(@RequestParam String email) {
        log.info("Verification status check for email: {}", email);
        return ResponseEntity.ok(authenticationService.getVerificationStatus(email));
    }
    
    /**
     * Resends verification email
     * @param email User email
     * @return Message indicating whether email was sent
     */
    @PostMapping("/resend-verification")
    public ResponseEntity<Map<String, Object>> resendVerificationEmail(@RequestParam String email) {
        log.info("Resend verification email request for: {}", email);
        boolean sent = userService.resendVerificationEmail(email);
        
        if (sent) {
            return ResponseEntity.ok(Map.of(
                "success", true,
                "message", "Verification email has been resent. Please check your inbox.",
                "timestamp", LocalDateTime.now()
            ));
        } else {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of(
                "success", false,
                "message", "Failed to resend verification email. Please try again later.",
                "timestamp", LocalDateTime.now()
            ));
        }
    }
    
    /**
     * Verifies user email with token
     * @param token Verification token
     * @return Verification result
     */
    @GetMapping("/verify/{token}")
    public ResponseEntity<String> verifyEmail(@PathVariable String token) {
        log.info("Email verification request with token");
        boolean verified = userService.verifyEmail(token);
        
        if (verified) {
            return ResponseEntity.ok("Email verified successfully. You can now log in.");
        } else {
            return ResponseEntity.badRequest().body("Invalid or expired verification token.");
        }
    }
} 