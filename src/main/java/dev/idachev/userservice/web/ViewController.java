package dev.idachev.userservice.web;

import dev.idachev.userservice.service.UserService;
import dev.idachev.userservice.web.dto.VerificationResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
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
@RequiredArgsConstructor
public class ViewController {

    private final UserService userService;
    
    @Value("${app.frontend.url}")
    private String frontendUrl;
    
    @Value("${app.frontend.routes.login}")
    private String loginRoute;
    
    @Value("${app.frontend.routes.register}")
    private String registerRoute;

    /**
     * Verifies email token and redirects to frontend with appropriate status
     * 
     * @param token Verification token
     * @return Redirect to frontend with verification status
     */
    @GetMapping("/api/v1/user/verify-email/{token}")
    public RedirectView verifyEmail(@PathVariable String token) {
        log.info("Processing email verification for token");

        try {
            // Verify first, then redirect - this is critical for ensuring verification happens
            VerificationResponse response = userService.verifyEmailAndGetResponse(token);
            String encodedMessage = URLEncoder.encode(response.getMessage(), StandardCharsets.UTF_8);
            
            // Build URL without including the token
            String redirectUrl;
            if (response.isSuccess()) {
                log.info("Email verification successful");
                redirectUrl = frontendUrl + loginRoute + "?verified=true&message=" + encodedMessage;
            } else {
                log.warn("Email verification failed");
                redirectUrl = frontendUrl + registerRoute + "?verified=false&message=" + encodedMessage;
            }
            
            // Redirect to frontend with status but without exposing token
            return new RedirectView(redirectUrl);
        } catch (Exception e) {
            log.error("Unexpected error during email verification: {}", e.getMessage(), e);
            String errorMessage = URLEncoder.encode("An unexpected error occurred. Please try again or contact support.", StandardCharsets.UTF_8);
            return new RedirectView(frontendUrl + registerRoute + "?verified=false&message=" + errorMessage);
        }
    }
} 