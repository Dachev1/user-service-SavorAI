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
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.view.RedirectView;

@Slf4j
@RestController
@RequestMapping("/api/v1/verification")
@Tag(name = "Email Verification", description = "Endpoints for email verification and status checking")
@Validated
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

    @GetMapping("/status")
    @Operation(summary = "Check verification status", description = "Returns verification status for a user email")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Status retrieved successfully"),
            @ApiResponse(responseCode = "404", description = "User not found",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    })
    public ResponseEntity<AuthResponse> getVerificationStatus(
            @RequestParam @NotBlank(message = "Email cannot be empty")
            @Email(message = "Email must be valid") String email) {

        log.info("Verification status check for email: {}", email);
        return ResponseEntity.ok(authenticationService.getVerificationStatus(email));
    }

    @PostMapping("/resend")
    @Operation(summary = "Resend verification email", description = "Sends a new verification email to the user")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Email sent successfully"),
            @ApiResponse(responseCode = "400", description = "Failed to send email or user already verified",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class))),
            @ApiResponse(responseCode = "404", description = "User not found",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    })
    public ResponseEntity<EmailVerificationResponse> resendVerificationEmail(@Valid @RequestBody EmailVerificationRequest request) {
        log.info("Resend verification email request for: {}", request.getEmail());
        return ResponseEntity.ok(userService.resendVerificationEmailWithResponse(request.getEmail()));
    }

    @GetMapping("/verify/{token}")
    @Operation(summary = "Verify email", description = "Verifies user email using token and redirects to login page")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "302", description = "Redirecting to login page with verification result")
    })
    public RedirectView verifyEmail(@PathVariable String token) {
        log.info("Email verification request with token");

        VerificationResult result = userService.verifyEmailForRedirect(token);
        log.info("Email verification result: {}", result.isSuccess());

        String loginUrl = getLoginUrl();
        if (!result.isSuccess()) {
            return new RedirectView(loginUrl + "?verified=false&error=" + result.getErrorType());
        }

        return new RedirectView(loginUrl + "?verified=true");
    }

    @PostMapping("/verify")
    @Operation(summary = "Verify email via API", description = "Verifies user email using token and returns verification response")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Verification processed"),
            @ApiResponse(responseCode = "400", description = "Invalid token format",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class))),
            @ApiResponse(responseCode = "404", description = "User with token not found",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    })
    public ResponseEntity<VerificationResponse> verifyEmailApi(@Valid @RequestBody TokenRequest request) {
        log.info("API email verification request with token");
        return ResponseEntity.ok(userService.verifyEmailAndGetResponse(request.getToken()));
    }

    private String getLoginUrl() {
        String baseUrl = (frontendUrl == null || frontendUrl.isEmpty()) ? "" : frontendUrl;
        return baseUrl + loginRoute;
    }
} 