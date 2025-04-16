package dev.idachev.userservice.web;

import dev.idachev.userservice.service.VerificationService;
import dev.idachev.userservice.web.dto.AuthResponse;
import dev.idachev.userservice.web.dto.GenericResponse;
import dev.idachev.userservice.web.dto.VerificationResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.view.RedirectView;

/**
 * Controller for email verification operations
 */
@RestController
@RequestMapping("/api/v1/verification")
@Tag(name = "Email Verification")
@Validated
public class VerificationController {

    private final VerificationService verificationService;

    @Value("${app.frontend.url}")
    private String frontendUrl;

    @Value("${app.frontend.routes.login:/signin}")
    private String signinRoute;
    
    @Autowired
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
            @RequestParam @NotBlank(message = "Email cannot be empty") 
            @Email(message = "Email must be valid") String email) {
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
            @RequestParam @NotBlank(message = "Email cannot be empty") 
            @Email(message = "Email must be valid") String email) {
        return ResponseEntity.ok(verificationService.resendVerificationEmail(email));
    }

    @GetMapping("/verify/{token}")
    @Operation(summary = "Verify email")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "302", description = "Redirecting to signin page with verification result")
    })
    public RedirectView verifyEmail(@PathVariable String token) {
        var result = verificationService.verifyEmailForRedirect(token);
        String redirectUrl = getSigninUrl() + 
                "?verified=" + result.isSuccess() + 
                (result.isSuccess() ? "" : "&error=" + result.getErrorType());
        return new RedirectView(redirectUrl);
    }

    @PostMapping("/verify")
    @Operation(summary = "Verify email via API")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Verification processed"),
            @ApiResponse(responseCode = "400", description = "Invalid token format"),
            @ApiResponse(responseCode = "404", description = "User with token not found")
    })
    public ResponseEntity<VerificationResponse> verifyEmailApi(@RequestParam String token) {
        return ResponseEntity.ok(verificationService.verifyEmailAndGetResponse(token));
    }

    private String getSigninUrl() {
        return (frontendUrl == null || frontendUrl.isEmpty() ? "" : frontendUrl) + signinRoute;
    }
}