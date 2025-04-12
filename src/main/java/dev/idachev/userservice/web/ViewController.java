package dev.idachev.userservice.web;

import dev.idachev.userservice.service.VerificationService;
import dev.idachev.userservice.web.dto.VerificationResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.view.RedirectView;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

/**
 * Controller for rendering view templates
 */
@Controller
@Slf4j
@Tag(name = "View Controller", description = "Endpoints for serving HTML views")
public class ViewController {

    @Value("${app.frontend.url:http://localhost:5173}")
    private String frontendUrl;

    @Value("${app.frontend.routes.login:/login}")
    private String signinRoute;

    private final VerificationService verificationService;

    @Autowired
    public ViewController(VerificationService verificationService) {
        this.verificationService = verificationService;
    }

    // Root path controllers for main application views
    
    @GetMapping("/")
    public String home() {
        return "index";
    }

    @GetMapping("/signin")
    public String signin() {
        return "signin";
    }

    @GetMapping("/signup")
    public String signup() {
        return "signup";
    }

    @GetMapping("/verify-success")
    public String verifySuccess() {
        return "verify-success";
    }

    @GetMapping("/verify-failure")
    public String verifyFailure() {
        return "verify-failure";
    }

    @GetMapping("/password-reset")
    public String passwordReset() {
        return "password-reset";
    }

    @GetMapping("/dashboard")
    public String dashboard() {
        return "dashboard";
    }

    @GetMapping("/contact")
    public String contact() {
        return "contact";
    }

    @GetMapping("/access-denied")
    public String accessDenied() {
        return "access-denied";
    }

    // Email verification API endpoints

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
            return new RedirectView(frontendUrl + "/signin?verified=false&message=" + message);
        }

        try {
            // Verify the token through service
            VerificationResponse response = verificationService.verifyEmailAndGetResponse(token);

            // Encode the message for URL
            String encodedMessage = URLEncoder.encode(response.getMessage(), StandardCharsets.UTF_8);

            // Direct redirect to the signin page
            String signinUrl = frontendUrl + "/signin?verified=" + response.isSuccess() + "&message=" + encodedMessage;

            log.info("Redirecting to signin page with status: {}", response.isSuccess());
            return new RedirectView(signinUrl);
        } catch (Exception e) {
            log.error("Error during email verification: {}", e.getMessage(), e);
            String encodedMessage = URLEncoder.encode(e.getMessage(), StandardCharsets.UTF_8);
            return new RedirectView(frontendUrl + "/signin?verified=false&message=" + encodedMessage);
        }
    }
} 