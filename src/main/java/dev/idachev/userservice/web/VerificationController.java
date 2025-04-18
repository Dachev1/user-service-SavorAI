package dev.idachev.userservice.web;

import dev.idachev.userservice.exception.ResourceNotFoundException;
import dev.idachev.userservice.exception.VerificationException;
import dev.idachev.userservice.service.VerificationService;
import dev.idachev.userservice.util.ResponseBuilder;
import dev.idachev.userservice.web.dto.AuthResponse;
import dev.idachev.userservice.web.dto.GenericResponse;
import dev.idachev.userservice.web.dto.VerificationResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.view.RedirectView;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

/**
 * Controller for email verification operations
 */
@RestController
@RequestMapping("/api/v1/verification")
@Tag(name = "Email Verification", description = "Endpoints for verifying user emails and resending verification links")
@Validated
@Slf4j
@RequiredArgsConstructor
public class VerificationController {

    private final VerificationService verificationService;

    @Value("${app.frontend.url:http://localhost:3000}")
    private String frontendUrl;

    @Value("${app.frontend.routes.login:/signin}")
    private String signinRoute;

    @GetMapping("/status")
    @Operation(summary = "Check verification status", description = "Check if a user account associated with an email is verified.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Status retrieved successfully. Body indicates if verified and includes JWT if so."),
            @ApiResponse(responseCode = "400", description = "Invalid email format"),
            @ApiResponse(responseCode = "404", description = "User not found with the given email")
    })
    public ResponseEntity<AuthResponse> getVerificationStatus(
            @RequestParam @NotBlank(message = "Email cannot be empty")
            @Email(message = "Email must be valid") String email) {
        return ResponseEntity.ok(verificationService.getVerificationStatus(email));
    }

    @PostMapping("/resend")
    @Operation(summary = "Resend verification email", description = "Requests a new verification email to be sent to the specified address.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Request processed. If email exists and is unverified, a new verification email will be sent."),
            @ApiResponse(responseCode = "400", description = "Invalid email format or account already verified"),
            @ApiResponse(responseCode = "404", description = "User not found with the given email")
    })
    public ResponseEntity<GenericResponse> resendVerificationEmail(
            @RequestParam @NotBlank(message = "Email cannot be empty")
            @Email(message = "Email must be valid") String email) {
        log.debug("Resend verification request for email: {}", email);
        verificationService.resendVerificationEmail(email);
        return ResponseEntity.ok(ResponseBuilder.success("Verification email resent. Please check your inbox."));
    }

    @GetMapping("/verify/{token}")
    @Operation(summary = "Verify email via link", description = "Verifies an email address using the token from the verification link. Redirects to the frontend sign-in page.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "302", description = "Redirecting to frontend sign-in page with verification result query parameters (?verified=true/false[&error=...])")
    })
    public RedirectView verifyEmailRedirect(@PathVariable @NotBlank String token) {
        String redirectUrl;
        try {
            log.debug("Attempting email verification via redirect with token: {}", token);
            verificationService.verifyEmail(token);
            log.info("Email successfully verified via redirect for token: {}", token);
            redirectUrl = getSigninUrl() + "?verified=true";
        } catch (VerificationException | ResourceNotFoundException e) {
            log.warn("Email verification failed via redirect for token {}: {}", token, e.getMessage());
            String encodedError = encodeUrlParameter(e.getMessage());
            redirectUrl = getSigninUrl() + "?verified=false&error=" + encodedError;
        } catch (Exception e) {
            log.error("Unexpected error during email verification via redirect for token {}: {}", token, e.getMessage(), e);
            String encodedError = encodeUrlParameter("Verification failed due to an unexpected error.");
            redirectUrl = getSigninUrl() + "?verified=false&error=" + encodedError;
        }
        
        log.debug("Redirecting verification to: {}", redirectUrl);
        return new RedirectView(redirectUrl);
    }

    @PostMapping("/verify")
    @Operation(summary = "Verify email via API call", description = "Verifies an email address using the provided token. Returns a JSON response.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Verification successful"),
            @ApiResponse(responseCode = "400", description = "Invalid or expired token, or account already verified")
    })
    public ResponseEntity<VerificationResponse> verifyEmailApi(@RequestParam @NotBlank String token) {
         try {
            log.debug("Attempting email verification via API with token: {}", token);
            verificationService.verifyEmail(token);
             log.info("Email successfully verified via API for token: {}", token);
            return ResponseEntity.ok(VerificationResponse.success("Your email has been verified successfully."));
        } catch (VerificationException | ResourceNotFoundException e) {
            log.warn("Email verification failed via API for token {}: {}", token, e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(VerificationResponse.failure(e.getMessage()));
        } catch (Exception e) {
            log.error("Unexpected error during email verification via API for token {}: {}", token, e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(VerificationResponse.failure("Verification failed due to an unexpected error."));
        }
    }

    private String getSigninUrl() {
        String base = (frontendUrl == null || frontendUrl.isBlank()) ? "" : frontendUrl.strip();
        String route = (signinRoute == null || signinRoute.isBlank()) ? "/signin" : signinRoute.strip();
        if (!route.startsWith("/")) route = "/" + route;
        if (base.endsWith("/")) base = base.substring(0, base.length() - 1);
        return base + route;
    }

    private String encodeUrlParameter(String value) {
        try {
            return URLEncoder.encode(value, StandardCharsets.UTF_8);
        } catch (Exception e) {
            log.error("Failed to URL encode parameter: {}", value, e);
            return "Error";
        }
    }
}