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
            String verificationUrl = buildVerificationUrl(verificationToken);
            
            Context context = new Context();
            context.setVariable("username", username);
            context.setVariable("verificationUrl", verificationUrl);
            context.setVariable("appName", appName);
            
            String emailContent = templateEngine.process("email/verification", context);
            
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");
            helper.setTo(to);
            helper.setSubject("Verify Your Email Address");
            helper.setText(emailContent, true);
            
            mailSender.send(message);
            log.info("Verification email sent to: {}", to);
        } catch (MessagingException e) {
            log.error("Failed to send verification email to: {}", to, e);
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
        return CompletableFuture.runAsync(() -> sendVerificationEmail(user));
    }
    
    /**
     * Sends welcome email to user after verification
     * 
     * @param user User to send welcome email to
     */
    public void sendWelcomeEmail(User user) {
        try {
            // Use the frontend URL with the login route
            String loginUrl = appUrl;
            if (!appUrl.endsWith("/") && !loginRoute.startsWith("/")) {
                loginUrl += "/";
            }
            loginUrl += loginRoute;
            
            Context context = new Context();
            context.setVariable("username", user.getUsername());
            context.setVariable("loginUrl", loginUrl);
            context.setVariable("appName", appName);
            
            String emailContent = templateEngine.process("email/welcome", context);
            
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");
            helper.setTo(user.getEmail());
            helper.setSubject("Welcome to " + appName + "!");
            helper.setText(emailContent, true);
            
            mailSender.send(message);
            log.info("Welcome email sent to: {}", user.getEmail());
        } catch (MessagingException e) {
            log.error("Failed to send welcome email to: {}", user.getEmail(), e);
            throw new RuntimeException("Failed to send welcome email", e);
        }
    }
    
    /**
     * Builds the verification URL for email tokens
     * 
     * @param token The verification token
     * @return The complete verification URL
     */
    private String buildVerificationUrl(String token) {
        // Use the server's own URL for verification (localhost:8081 or production URL)
        // This way the request first hits the backend for verification before redirecting to frontend
        return "http://localhost:8081/api/v1/user/verify-email/" + token;
    }
} 
