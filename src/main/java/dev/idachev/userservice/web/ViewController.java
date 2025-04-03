package dev.idachev.userservice.web;

import dev.idachev.userservice.service.VerificationService;
import dev.idachev.userservice.web.dto.VerificationResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.servlet.view.RedirectView;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

@Slf4j
@Controller
@Tag(name = "Email Verification Views", description = "Endpoints for email verification with frontend redirects")
public class ViewController {

    private final VerificationService verificationService;

    @Autowired
    public ViewController(VerificationService verificationService) {
        this.verificationService = verificationService;
    }

    @GetMapping("/api/v1/user/verify-email/")
    @Operation(summary = "Handle missing token",
            description = "Handles case when no verification token is provided and redirects to signin page")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "302", description = "Redirects to signin page with error result")
    })
    public RedirectView handleMissingToken() {
        log.info("Email verification request with missing token");
        String message = URLEncoder.encode("Invalid or missing verification token", StandardCharsets.UTF_8);
        return new RedirectView("http://localhost:5173/signin?verified=false&message=" + message);
    }

    @GetMapping("/api/v1/user/verify-email/{token}")
    @Operation(summary = "Verify email with frontend redirect",
            description = "Verifies email token and redirects to frontend signin page")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "302", description = "Redirects to signin page with verification result")
    })
    public RedirectView verifyEmail(@PathVariable String token) {
        log.info("Processing email verification for token");

        // Default values if token is empty
        if (token == null || token.trim().isEmpty()) {
            String message = URLEncoder.encode("Invalid or missing verification token", StandardCharsets.UTF_8);
            return new RedirectView("http://localhost:5173/signin?verified=false&message=" + message);
        }

        // Verify the token through service
        VerificationResponse response = verificationService.verifyEmailAndGetResponse(token);

        // Encode the message for URL
        String encodedMessage = URLEncoder.encode(response.getMessage(), StandardCharsets.UTF_8);

        // Direct redirect to the signin page
        String signinUrl = "http://localhost:5173/signin?verified=" + response.isSuccess() + "&message=" + encodedMessage;

        log.info("Redirecting to signin page with status: {}", response.isSuccess());
        return new RedirectView(signinUrl);
    }
} 