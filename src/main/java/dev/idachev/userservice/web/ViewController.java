package dev.idachev.userservice.web;

import dev.idachev.userservice.service.VerificationService;
import dev.idachev.userservice.web.dto.VerificationResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.servlet.view.RedirectView;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

/**
 * Controller for rendering view templates
 */
@Controller
@Slf4j
public class ViewController {

    @Value("${app.frontend.url:http://localhost:5173}")
    private String frontendUrl;

    private final VerificationService verificationService;

    public ViewController(VerificationService verificationService) {
        this.verificationService = verificationService;
    }

    // Basic view mappings
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

    // Email verification endpoint
    @GetMapping({"/api/v1/user/verify-email/", "/api/v1/user/verify-email/{token}"})
    public RedirectView verifyEmail(@PathVariable(required = false) String token) {
        log.info("Processing email verification request");

        // Handle missing or empty token
        if (token == null || token.trim().isEmpty()) {
            String message = URLEncoder.encode("Invalid or missing verification token", StandardCharsets.UTF_8);
            return new RedirectView(frontendUrl + "/signin?verified=false&message=" + message);
        }

        // Verify the token - service handles all exceptions internally
        VerificationResponse response = verificationService.verifyEmailAndGetResponse(token);
        String encodedMessage = URLEncoder.encode(response.getMessage(), StandardCharsets.UTF_8);
        return new RedirectView(frontendUrl + "/signin?verified=" + response.isSuccess() + "&message=" + encodedMessage);
    }
} 