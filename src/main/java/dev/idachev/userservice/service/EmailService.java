package dev.idachev.userservice.service;

import dev.idachev.userservice.model.User;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

import java.util.UUID;
import java.util.concurrent.CompletableFuture;

/**
 * Service for email operations and management
 */
@Slf4j
@Service
public class EmailService {
    
    private final JavaMailSender mailSender;
    private final TemplateEngine templateEngine;
    
    @Value("${app.frontend.url}")
    private String appUrl;
    
    @Value("${app.frontend.routes.login}")
    private String loginRoute;
    
    @Value("${spring.application.name:SavorAI}")
    private String appName;
    
    @Value("${server.port:8081}")
    private String serverPort;
    
    @Value("${app.service.url:http://localhost}")
    private String serviceUrl;
    
    @Autowired
    public EmailService(JavaMailSender mailSender, TemplateEngine templateEngine) {
        this.mailSender = mailSender;
        this.templateEngine = templateEngine;
    }
    
    /**
     * Creates verification token for a user
     * 
     * @return New UUID string token
     */
    public String generateVerificationToken() {
        return UUID.randomUUID().toString();
    }
    
    /**
     * Sends verification email to user
     * 
     * @param user User to send verification email to
     */
    public void sendVerificationEmail(User user) {
        if (user == null) {
            log.error("Cannot send verification email to null user");
            throw new IllegalArgumentException("User cannot be null");
        }
        
        if (user.getEmail() == null || user.getEmail().trim().isEmpty()) {
            log.error("Cannot send verification email to user with empty email");
            throw new IllegalArgumentException("User email cannot be empty");
        }
        
        sendVerificationEmail(user.getEmail(), user.getUsername(), user.getVerificationToken());
    }
    
    /**
     * Sends verification email to user
     * 
     * @param to User's email address
     * @param username User's username
     * @param verificationToken Verification token
     */
    public void sendVerificationEmail(String to, String username, String verificationToken) {
        try {
            // Input validation
            if (to == null || to.trim().isEmpty()) {
                throw new IllegalArgumentException("Email address cannot be empty");
            }
            
            if (verificationToken == null || verificationToken.trim().isEmpty()) {
                throw new IllegalArgumentException("Verification token cannot be empty");
            }
            
            String verificationUrl = buildVerificationUrl(verificationToken);
            log.debug("Sending verification email to {} with URL: {}", to, verificationUrl);
            
            Context context = new Context();
            context.setVariable("username", username != null ? username : "User");
            context.setVariable("verificationUrl", verificationUrl);
            context.setVariable("appName", appName);
            
            String emailContent = templateEngine.process("email/verification", context);
            
            sendEmail(to, "Verify Your Email Address", emailContent);
            log.info("Verification email sent successfully to: {}", to);
        } catch (Exception e) {
            log.error("Failed to send verification email to: {} - Error: {}", to, e.getMessage(), e);
            throw new RuntimeException("Failed to send verification email", e);
        }
    }
    
    /**
     * Sends verification email asynchronously
     * 
     * @param user User to send verification email to
     * @return CompletableFuture for tracking completion
     */
    @Async
    public CompletableFuture<Void> sendVerificationEmailAsync(User user) {
        return CompletableFuture.runAsync(() -> {
            try {
                sendVerificationEmail(user);
            } catch (Exception e) {
                log.error("Async verification email failed for user {}: {}", 
                        user != null ? user.getEmail() : "null", e.getMessage(), e);
                // We don't rethrow in async context
            }
        });
    }
    
    /**
     * Helper method to send an email with HTML content
     * 
     * @param to Recipient email address
     * @param subject Email subject
     * @param htmlContent HTML content of the email
     * @throws MessagingException If there is an error creating or sending the email
     */
    private void sendEmail(String to, String subject, String htmlContent) throws MessagingException {
        MimeMessage message = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");
        helper.setTo(to);
        helper.setSubject(subject);
        helper.setText(htmlContent, true);
        
        mailSender.send(message);
    }
    
    /**
     * Builds the verification URL for email tokens
     * 
     * @param token The verification token
     * @return The complete verification URL
     */
    private String buildVerificationUrl(String token) {
        // Use the service URL from configuration - fallback to localhost with configured port
        StringBuilder baseUrl = new StringBuilder(serviceUrl);
        
        // If serviceUrl doesn't include port, add it (only for localhost)
        if (serviceUrl.contains("localhost") && !serviceUrl.contains(":")) {
            baseUrl.append(":").append(serverPort);
        }
        
        // Ensure proper path formatting
        if (!baseUrl.toString().endsWith("/")) {
            baseUrl.append("/");
        }
        
        baseUrl.append("api/v1/user/verify-email/").append(token);
        
        String url = baseUrl.toString();
        log.debug("Built verification URL: {}", url);
        return url;
    }
    
    /**
     * Builds a frontend URL with the given route
     * 
     * @param route The frontend route
     * @return The complete frontend URL
     */
    private String buildFrontendUrl(String route) {
        if (route == null) {
            route = "";
        }
        
        StringBuilder url = new StringBuilder(appUrl);
        
        // Ensure proper URL formatting with slash
        if (!appUrl.endsWith("/") && !route.startsWith("/")) {
            url.append("/");
        }
        
        // Don't add double slashes
        if (appUrl.endsWith("/") && route.startsWith("/")) {
            url.append(route.substring(1));
        } else {
            url.append(route);
        }
        
        String result = url.toString();
        log.debug("Built frontend URL: {}", result);
        return result;
    }
} 
