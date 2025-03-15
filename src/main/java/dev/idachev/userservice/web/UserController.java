package dev.idachev.userservice.web;

import dev.idachev.userservice.service.AuthenticationService;
import dev.idachev.userservice.service.UserService;
import dev.idachev.userservice.web.dto.*;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;

@Slf4j
@RestController
@RequestMapping("/api/v1/user")
@Tag(name = "User Management", description = "Endpoints for user registration, authentication, and management")
public class UserController {

    private final UserService userService;
    private final AuthenticationService authenticationService;

    @Autowired
    public UserController(UserService userService, AuthenticationService authenticationService) {
        this.userService = userService;
        this.authenticationService = authenticationService;
    }

    /**
     * Registers a new user
     *
     * @param request User registration details
     * @return Auth response with JWT token and verification status
     */
    @PostMapping("/register")
    @Operation(summary = "Register new user", description = "Creates a new user account and sends verification email")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "201", description = "User registered successfully"),
            @ApiResponse(responseCode = "400", description = "Invalid input data",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class))),
            @ApiResponse(responseCode = "409", description = "Username or email already exists",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    })
    public ResponseEntity<AuthResponse> register(@Valid @RequestBody RegisterRequest request) {

        log.info("Registration request received for email: {}", request.getEmail());
        return ResponseEntity.status(HttpStatus.CREATED).body(userService.register(request));
    }

    /**
     * Authenticates a user
     *
     * @param request Login credentials
     * @return Auth response with JWT token
     */
    @PostMapping("/login")
    @Operation(summary = "Authenticate user", description = "Validates credentials and returns JWT token")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Authentication successful"),
            @ApiResponse(responseCode = "400", description = "Invalid input or already logged in",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class))),
            @ApiResponse(responseCode = "401", description = "Invalid credentials",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    })
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest request) {

        log.info("Login request received for email: {}", request.getEmail());
        return ResponseEntity.ok(authenticationService.login(request));
    }

    @GetMapping("/current-user")
    @Operation(summary = "Get current user", description = "Returns information about the currently authenticated user")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "User information retrieved"),
            @ApiResponse(responseCode = "401", description = "User not authenticated",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    })
    public ResponseEntity<UserResponse> getCurrentUser() {

        log.debug("Current user information requested");
        return ResponseEntity.ok(authenticationService.getCurrentUserInfo());
    }

    @PostMapping("/logout")
    @Operation(summary = "Logout user", description = "Logs out the current user and invalidates session")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Successfully logged out")
    })
    public ResponseEntity<ErrorResponse> logout(@RequestHeader("Authorization") String token) {
        log.info("Logout request received");
        return ResponseEntity.ok(authenticationService.logout(token));
    }

    /**
     * Checks user verification status
     *
     * @param email User email
     * @return Auth response with verification status
     */
    @GetMapping("/verification-status")
    @Operation(summary = "Check verification status", description = "Returns verification status for a user email")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Status retrieved successfully"),
            @ApiResponse(responseCode = "404", description = "User not found",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    })
    public ResponseEntity<AuthResponse> getVerificationStatus(@RequestParam String email) {
        log.info("Verification status check for email: {}", email);
        return ResponseEntity.ok(authenticationService.getVerificationStatus(email));
    }

    /**
     * Resends verification email
     *
     * @param email User email
     * @return Message indicating whether email was sent
     */
    @PostMapping("/resend-verification")
    @Operation(summary = "Resend verification email", description = "Sends a new verification email to the user")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Email sent successfully"),
            @ApiResponse(responseCode = "400", description = "Failed to send email or user already verified",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class))),
            @ApiResponse(responseCode = "404", description = "User not found",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    })
    public ResponseEntity<EmailVerificationResponse> resendVerificationEmail(@RequestParam String email) {
        log.info("Resend verification email request for: {}", email);
        boolean sent = userService.resendVerificationEmail(email);

        EmailVerificationResponse response = new EmailVerificationResponse(
                sent,
                sent ? "Verification email has been resent. Please check your inbox."
                        : "Failed to resend verification email. Please try again later.",
                LocalDateTime.now()
        );

        return ResponseEntity.ok(response);
    }

    /**
     * Verifies user email with token
     *
     * @param token Verification token
     * @return Verification result
     */
    @GetMapping("/verify/{token}")
    @Operation(summary = "Verify email", description = "Verifies user email using token")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Email verified successfully"),
            @ApiResponse(responseCode = "400", description = "Invalid or expired token")
    })
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