package dev.idachev.userservice.web;

import dev.idachev.userservice.service.UserService;
import dev.idachev.userservice.service.AuthenticationService;
import dev.idachev.userservice.web.dto.AuthResponse;
import dev.idachev.userservice.web.dto.EmailVerificationResponse;
import dev.idachev.userservice.web.dto.ErrorResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.view.RedirectView;

import java.time.LocalDateTime;

@Slf4j
@RestController
@RequestMapping("/api/v1/verification")
@Tag(name = "Email Verification", description = "Endpoints for email verification and status checking")
public class VerificationController {

    private final UserService userService;
    private final AuthenticationService authenticationService;
    
    @Value("${app.frontend.url}")
    private String frontendUrl;
    
    @Value("${app.frontend.routes.login:/login}")
    private String loginRoute;

    @Autowired
    public VerificationController(UserService userService, AuthenticationService authenticationService) {
        this.userService = userService;
        this.authenticationService = authenticationService;
    }

    /**
     * Checks user verification status
     *
     * @param email User email
     * @return Auth response with verification status
     */
    @GetMapping("/status")
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
    @PostMapping("/resend")
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
     * Verifies user email with token and redirects to login page
     *
     * @param token Verification token
     * @return Redirect to login page
     */
    @GetMapping("/verify/{token}")
    @Operation(summary = "Verify email", description = "Verifies user email using token and redirects to login page")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "302", description = "Redirecting to login page with verification result")
    })
    public RedirectView verifyEmail(@PathVariable String token) {
        log.info("Email verification request with token");
        
        // Build redirect URL
        String redirectUrl = buildLoginUrl();
        
        try {
            boolean verified = userService.verifyEmail(token);
            return new RedirectView(redirectUrl + "?verified=" + verified);
        } catch (Exception e) {
            log.error("Error during verification: {}", e.getMessage());
            return new RedirectView(redirectUrl + "?verified=false&error=verificationFailed");
        }
    }
    
    /**
     * Helper method to build the frontend login URL
     */
    private String buildLoginUrl() {
        StringBuilder url = new StringBuilder(frontendUrl);
        
        // Ensure proper URL formatting
        if (!frontendUrl.endsWith("/") && !loginRoute.startsWith("/")) {
            url.append("/");
        }
        url.append(loginRoute);
        
        return url.toString();
    }
} 