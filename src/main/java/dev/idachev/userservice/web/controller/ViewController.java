package dev.idachev.userservice.web.controller;

import dev.idachev.userservice.service.UserService;
import dev.idachev.userservice.web.dto.VerificationResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

/**
 * Controller for handling views rendered with Thymeleaf templates
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
     * Handles email verification and displays the appropriate template
     */
    @GetMapping("/api/v1/user/verify/{token}")
    public String verifyEmail(@PathVariable String token, Model model) {
        log.debug("Processing email verification for token: {}", token);
        VerificationResponse response = userService.verifyEmailAndGetResponse(token);
        
        // Common attributes
        model.addAttribute("message", response.getMessage());
        model.addAttribute("verificationStatus", response.isSuccess() ? "success" : "failure");
        
        if (response.isSuccess()) {
            model.addAttribute("title", "Email Verified");
            model.addAttribute("frontendUrl", frontendUrl + loginRoute);
            return "verification-success";
        } else {
            model.addAttribute("title", "Verification Failed");
            model.addAttribute("frontendUrl", frontendUrl + registerRoute);
            return "verification-failure";
        }
    }
} 