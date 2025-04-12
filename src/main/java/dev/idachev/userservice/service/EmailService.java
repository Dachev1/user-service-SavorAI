package dev.idachev.userservice.service;

import dev.idachev.userservice.model.User;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.thymeleaf.spring6.SpringTemplateEngine;
import org.thymeleaf.context.Context;

import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

/**
 * Email service handling all email communication
 */
@Service
@Slf4j
public class EmailService {

    private final JavaMailSender mailSender;
    private final SpringTemplateEngine templateEngine;

    @Value("${spring.application.name:SavorAI}")
    private String appName;

    @Value("${server.port:8081}")
    private String serverPort;

    @Value("${app.service.url:http://localhost}")
    private String serviceUrl;

    @Value("${contact.email.recipient:appsavorai@gmail.com}")
    private String defaultContactRecipient;

    @Value("${spring.mail.username}")
    private String fromEmail;

    public EmailService(JavaMailSender mailSender, SpringTemplateEngine templateEngine) {
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
     * @param to                User's email address
     * @param username          User's username
     * @param verificationToken Verification token
     */
    public void sendVerificationEmail(String to, String username, String verificationToken) {
        try {
            String verificationUrl = buildVerificationUrl(verificationToken);
            log.debug("Sending verification email to {} with URL: {}", to, verificationUrl);

            Context context = new Context();
            context.setVariable("username", Optional.ofNullable(username).orElse("User"));
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
     * @param subject     Email subject
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

    /**
     * Sends contact form email to the default recipient
     *
     * @param fromEmail Sender's email address
     * @param subject   Email subject
     * @param message   Email message
     */
    public void sendContactFormEmail(String fromEmail, String subject, String message) {
        sendContactFormEmail(defaultContactRecipient, fromEmail, subject, message);
    }

    /**
     * Sends contact form email to a specified recipient
     *
     * @param to        Recipient email address
     * @param fromEmail Sender's email address
     * @param subject   Email subject
     * @param message   Email message
     */
    public void sendContactFormEmail(String to, String fromEmail, String subject, String message) {
        try {
            // Use default recipient if none provided
            String recipient = to != null ? to : defaultContactRecipient;

            log.debug("Sending contact form email from {} to {}", fromEmail, recipient);

            Context context = new Context();
            context.setVariable("fromEmail", fromEmail);
            context.setVariable("subject", subject);
            context.setVariable("message", message);
            context.setVariable("appName", appName);

            String emailContent = templateEngine.process("email/contact-form", context);

            sendEmail(recipient, "Contact Form: " + subject, emailContent);
            log.info("Contact form email sent successfully from: {} to: {}", fromEmail, recipient);
        } catch (Exception e) {
            log.error("Failed to send contact form email from: {} to: {} - Error: {}", fromEmail, to, e.getMessage(), e);
            throw new RuntimeException("Failed to send contact form email", e);
        }
    }

    /**
     * Sends contact form email asynchronously
     *
     * @param fromEmail Sender's email address
     * @param subject   Email subject
     * @param message   Email message
     * @return CompletableFuture for tracking completion
     */
    @Async
    public CompletableFuture<Void> sendContactFormEmailAsync(String fromEmail, String subject, String message) {
        return CompletableFuture.runAsync(() -> {
            try {
                // No validation here - rely on DTO validation
                sendContactFormEmail(fromEmail, subject, message);
            } catch (Exception e) {
                log.error("Async contact form email failed: {}", e.getMessage(), e);
                // We don't rethrow in async context to avoid unhandled exceptions
            }
        });
    }
} 
