package dev.idachev.userservice.service;

import dev.idachev.userservice.config.EmailProperties;
import dev.idachev.userservice.exception.EmailSendException;
import dev.idachev.userservice.model.User;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.thymeleaf.context.Context;
import org.thymeleaf.spring6.SpringTemplateEngine;

/**
 * Email service handling all email communication.
 * Assumes @EnableAsync is configured elsewhere.
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class EmailService {

    private final JavaMailSender mailSender;
    private final SpringTemplateEngine templateEngine;
    private final EmailProperties emailProperties;

    /**
     * Sends verification email to user.
     * Accepts the full verification URL.
     * This operation is SYNCHRONOUS - consider making it async if needed.
     * Throws EmailSendException on failure.
     */
    public void sendVerificationEmail(User user, String verificationUrl) {
        if (user == null || user.getEmail() == null || user.getEmail().isEmpty()) {
            log.warn("Cannot send verification email to null user or empty email");
            return;
        }
        if (verificationUrl == null || verificationUrl.isBlank()) {
            log.warn("Cannot send verification email with blank verification URL");
            return;
        }

        log.debug("Attempting to send verification email to {}", user.getEmail());
        Context context = new Context();
        context.setVariable("username", user.getUsername());
        context.setVariable("verificationUrl", verificationUrl);
        context.setVariable("appName", emailProperties.getAppName());
        context.setVariable("supportEmail", emailProperties.getContactRecipient());

        String htmlContent = templateEngine.process("email/verification", context);

        sendEmail(
                user.getEmail(),
                emailProperties.getAppName() + " - Verify Your Email",
                htmlContent
        );
        log.info("Verification email sent successfully to {}", user.getEmail());
    }

    /**
     * Sends contact form email to the default recipient.
     * This operation is SYNCHRONOUS - consider making it async if needed.
     * Throws EmailSendException on failure.
     */
    public void sendContactFormEmail(String fromUserEmail, String subject, String message) {
        sendContactFormEmail(emailProperties.getContactRecipient(), fromUserEmail, subject, message);
    }

    /**
     * Sends contact form email to a specified recipient.
     * This operation is SYNCHRONOUS - consider making it async if needed.
     * Throws EmailSendException on failure.
     */
    public void sendContactFormEmail(String toRecipient, String fromUserEmail, String subject, String message) {
        log.debug("Attempting to send contact form email from {} to {}", fromUserEmail, toRecipient);
        Context context = new Context();
        context.setVariable("fromEmail", fromUserEmail);
        context.setVariable("subject", subject);
        context.setVariable("message", message);
        context.setVariable("appName", emailProperties.getAppName());

        String htmlContent = templateEngine.process("email/contact-form", context);

        sendEmail(
                toRecipient,
                "Contact Form [" + emailProperties.getAppName() + "]: " + subject,
                htmlContent
        );
        log.info("Contact form email sent successfully from: {} to: {}", fromUserEmail, toRecipient);
    }

    /**
     * Helper method to send an email with HTML content.
     * Made asynchronous to avoid blocking caller threads.
     * Requires @EnableAsync on a @Configuration class.
     */
    @Async
    private void sendEmail(String to, String subject, String htmlContent) {
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            helper.setFrom(emailProperties.getFromAddress());
            helper.setTo(to);
            helper.setSubject(subject);
            helper.setText(htmlContent, true);

            mailSender.send(message);
            log.info("Successfully sent email to {} with subject: {}", to, subject);
        } catch (MessagingException e) {
            // Log error from async operation
            log.error("Asynchronous email sending failed to {} with subject \"{}\": {}",
                    to, subject, e.getMessage(), e);
            // Consider sending notification / adding to retry queue if needed
            // Cannot throw exception back to caller easily from void @Async method
        }
    }
} 
