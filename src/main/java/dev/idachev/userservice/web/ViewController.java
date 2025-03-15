package dev.idachev.userservice.web;

import dev.idachev.userservice.service.UserService;
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

/**
 * Controller for handling email verification redirects to frontend
 */
@Slf4j
@Controller
@Tag(name = "Email Verification Views", description = "Endpoints for email verification with frontend redirects")
public class ViewController {

    private final UserService userService;

    @Autowired
    public ViewController(UserService userService) {
        this.userService = userService;
    }

    /**
     * Verifies email token and redirects to frontend login page
     *
     * @param token Verification token
     * @return Redirect to frontend login page with verification status
     */
    @GetMapping("/api/v1/user/verify-email/{token}")
    @Operation(summary = "Verify email with frontend redirect",
            description = "Verifies email token and redirects to frontend login page")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "302", description = "Redirects to login page with verification result")
    })
    public RedirectView verifyEmail(@PathVariable String token) {
        log.info("Processing email verification for token");

        // Default values for invalid token
        boolean verified = false;
        String message = "Invalid or missing verification token";

        // Try to verify the token if it's not empty
        if (token != null && !token.trim().isEmpty()) {
            try {
                VerificationResponse response = userService.verifyEmailAndGetResponse(token);
                verified = response.isSuccess();
                message = response.getMessage();
            } catch (Exception e) {
                log.error("Error during verification: {}", e.getMessage());
                message = "Verification failed: " + e.getMessage();
            }
        }

        // Encode the message for URL
        String encodedMessage = URLEncoder.encode(message, StandardCharsets.UTF_8);

        // Direct redirect to the login page
        String loginUrl = "http://localhost:5173/login?verified=" + verified + "&message=" + encodedMessage;

        log.info("Redirecting to login page with status: {}", verified);
        return new RedirectView(loginUrl);
    }
} 