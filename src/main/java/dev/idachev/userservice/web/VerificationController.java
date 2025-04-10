package dev.idachev.userservice.web;

import dev.idachev.userservice.service.VerificationService;
import dev.idachev.userservice.web.dto.AuthResponse;
import dev.idachev.userservice.web.dto.GenericResponse;
import dev.idachev.userservice.web.dto.VerificationResponse;
import dev.idachev.userservice.web.dto.VerificationResult;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.view.RedirectView;

/**
 * Controller for all email verification operations
 */
@Slf4j
@RestController
@RequestMapping("/api/v1/verification")
@Tag(name = "Email Verification", description = "Endpoints for email verification and status checking")
@Validated
public class VerificationController {

    private final VerificationService verificationService;

    @Value("${app.frontend.url}")
    private String frontendUrl;

    @Value("${app.frontend.routes.login:/signin}")
    private String signinRoute;

    public VerificationController(VerificationService verificationService) {
        this.verificationService = verificationService;
    }

    @GetMapping("/status")
    @Operation(summary = "Check verification status")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Status retrieved successfully"),
            @ApiResponse(responseCode = "404", description = "User not found")
    })
    public ResponseEntity<AuthResponse> getVerificationStatus(
            @RequestParam @NotBlank(message = "Email cannot be empty") @Email(message = "Email must be valid") String email) {
        log.info("Verification status check for email: {}", email);
        return ResponseEntity.ok(verificationService.getVerificationStatus(email));
    }

    @PostMapping("/resend")
    @Operation(summary = "Resend verification email")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Email sent successfully"),
            @ApiResponse(responseCode = "400", description = "Failed to send email or user already verified"),
            @ApiResponse(responseCode = "404", description = "User not found")
    })
    public ResponseEntity<GenericResponse> resendVerificationEmail(
            @RequestParam @NotBlank(message = "Email cannot be empty") @Email(message = "Email must be valid") String email) {
        log.info("Resend verification email request for: {}", email);
        return ResponseEntity.ok(verificationService.resendVerificationEmail(email));
    }

    @GetMapping("/verify/{token}")
    @Operation(summary = "Verify email")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "302", description = "Redirecting to signin page with verification result")
    })
    public RedirectView verifyEmail(@PathVariable String token) {
        log.info("Email verification request with token");
        VerificationResult result = verificationService.verifyEmailForRedirect(token);
        log.info("Email verification result: {}", result.isSuccess());

        String signinUrl = getSigninUrl();
        if (!result.isSuccess()) {
            return new RedirectView(signinUrl + "?verified=false&error=" + result.getErrorType());
        }
        return new RedirectView(signinUrl + "?verified=true");
    }

    @PostMapping("/verify")
    @Operation(summary = "Verify email via API")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Verification processed"),
            @ApiResponse(responseCode = "400", description = "Invalid token format"),
            @ApiResponse(responseCode = "404", description = "User with token not found")
    })
    public ResponseEntity<VerificationResponse> verifyEmailApi(@RequestParam String token) {
        log.info("API email verification request with token");
        return ResponseEntity.ok(verificationService.verifyEmailAndGetResponse(token));
    }

    private String getSigninUrl() {
        String baseUrl = (frontendUrl == null || frontendUrl.isEmpty()) ? "" : frontendUrl;
        return baseUrl + signinRoute;
    }
}