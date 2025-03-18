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

import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

@Slf4j
@Service
public class EmailService {

    private final JavaMailSender mailSender;
    private final TemplateEngine templateEngine;

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
     * @param to                User's email address
     * @param username          User's username
     * @param verificationToken Verification token
     */
    public void sendVerificationEmail(String to, String username, String verificationToken) {
        // Input validation
        if (to == null || to.trim().isEmpty()) {
            throw new IllegalArgumentException("Email address cannot be empty");
        }

        if (verificationToken == null || verificationToken.trim().isEmpty()) {
            throw new IllegalArgumentException("Verification token cannot be empty");
        }

        try {
            String verificationUrl = buildVerificationUrl(verificationToken);
            log.debug("Sending verification email to {} with URL: {}", to, verificationUrl);

            Context context = new Context();
            context.setVariable("username", Optional.ofNullable(username).orElse("User"));
            context.setVariable("verificationUrl", verificationUrl);
            context.setVariable("appName", appName);

            String emailContent = templateEngine.process("email/verification", context);

            sendEmail(to, emailContent);
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
                if (user == null) {
                    log.error("Async verification email failed: user is null");
                    throw new IllegalArgumentException("User cannot be null for verification email");
                }
                sendVerificationEmail(user);
            } catch (Exception e) {
                String email = user != null ? user.getEmail() : "null";
                log.error("Async verification email failed for user {}: {}", email, e.getMessage());
                // We don't rethrow in async context to avoid unhandled exceptions
            }
        });
    }

    /**
     * Helper method to send an email with HTML content
     *
     * @param to          Recipient email address
     * @param htmlContent HTML content of the email
     * @throws MessagingException If there is an error creating or sending the email
     */
    private void sendEmail(String to, String htmlContent) throws MessagingException {
        MimeMessage message = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

        helper.setTo(to);
        helper.setSubject("Verify Your Email Address");
        helper.setText(htmlContent, true);

        mailSender.send(message);
    }

    /**
     * Builds the verification URL with the token
     *
     * @param token Verification token
     * @return Complete verification URL
     */
    private String buildVerificationUrl(String token) {
        if (serviceUrl != null && serviceUrl.contains("localhost")) {
            return String.format("http://localhost:%s/api/v1/verification/verify/%s", serverPort, token);
        }

        // For other environments, use regular formatting
        String baseUrl = serviceUrl;
        if (baseUrl == null || baseUrl.isEmpty()) {
            baseUrl = "http://localhost:" + serverPort;
        }

        // Ensure no trailing slash in base URL
        if (baseUrl.endsWith("/")) {
            baseUrl = baseUrl.substring(0, baseUrl.length() - 1);
        }

        String url = baseUrl + "/api/v1/verification/verify/" + token;
        log.debug("Built verification URL: {}", url);
        return url;
    }
} 
