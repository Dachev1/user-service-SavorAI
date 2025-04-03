package dev.idachev.userservice.service;

import dev.idachev.userservice.model.User;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.test.util.ReflectionTestUtils;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class EmailServiceUTest {

    @Mock
    private JavaMailSender mailSender;

    @Mock
    private TemplateEngine templateEngine;

    @Mock
    private MimeMessage mimeMessage;

    @InjectMocks
    private EmailService emailService;

    private User testUser;
    private String testToken;

    @BeforeEach
    void setUp() {
        testUser = new User();
        testUser.setId(UUID.randomUUID());
        testUser.setUsername("testuser");
        testUser.setEmail("test@example.com");
        testUser.setVerificationToken("verification-token");

        testToken = UUID.randomUUID().toString();

        // Set required properties using reflection
        ReflectionTestUtils.setField(emailService, "appName", "SavorAI");
        ReflectionTestUtils.setField(emailService, "serverPort", "8081");
        ReflectionTestUtils.setField(emailService, "serviceUrl", "http://localhost");
        ReflectionTestUtils.setField(emailService, "defaultContactRecipient", "appsavorai@gmail.com");
    }

    @Test
    void generateVerificationToken_ReturnsValidUUID() {
        // When
        String token = emailService.generateVerificationToken();

        // Then
        assertNotNull(token);
        assertTrue(token.matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"));
    }

    @Test
    void sendVerificationEmail_Success() throws MessagingException {
        // Given
        String expectedHtmlContent = "<html>Verification Email</html>";
        when(mailSender.createMimeMessage()).thenReturn(mimeMessage);
        when(templateEngine.process(anyString(), any(Context.class))).thenReturn(expectedHtmlContent);

        // When
        emailService.sendVerificationEmail(testUser);

        // Then
        verify(mailSender).send(any(MimeMessage.class));
        verify(templateEngine).process(eq("email/verification"), any(Context.class));
    }

    @Test
    void sendVerificationEmail_WithNullUsername() throws MessagingException {
        // Given
        testUser.setUsername(null);
        when(mailSender.createMimeMessage()).thenReturn(mimeMessage);
        when(templateEngine.process(anyString(), any(Context.class))).thenReturn("<html>Email</html>");

        // When
        emailService.sendVerificationEmail(testUser);

        // Then
        verify(mailSender).send(any(MimeMessage.class));
        verify(templateEngine).process(eq("email/verification"), any(Context.class));
    }

    @Test
    void sendVerificationEmailAsync_ReturnsCompletableFuture() throws ExecutionException, InterruptedException, TimeoutException {
        // Given
        when(mailSender.createMimeMessage()).thenReturn(mimeMessage);
        when(templateEngine.process(anyString(), any(Context.class))).thenReturn("<html>Email</html>");
        // Use doNothing() for void methods when mocking async behavior to avoid potential issues
        doNothing().when(mailSender).send(any(MimeMessage.class));

        // When
        CompletableFuture<Void> future = emailService.sendVerificationEmailAsync(testUser);

        // Then
        assertNotNull(future);

        // Wait for the future to complete to ensure the async task runs
        future.get(5, TimeUnit.SECONDS); // Wait for completion with a timeout

        assertFalse(future.isCompletedExceptionally());

        // Verify interactions happened within the async task
        verify(mailSender).send(any(MimeMessage.class));
        verify(templateEngine).process(eq("email/verification"), any(Context.class));
    }

    @Test
    void sendContactFormEmail_Success() throws MessagingException {
        // Given
        String fromEmail = "sender@example.com";
        String subject = "Test Subject";
        String message = "Test Message";
        String expectedHtmlContent = "<html>Contact Form</html>";

        when(mailSender.createMimeMessage()).thenReturn(mimeMessage);
        when(templateEngine.process(anyString(), any(Context.class))).thenReturn(expectedHtmlContent);

        // When
        emailService.sendContactFormEmail(fromEmail, subject, message);

        // Then
        verify(mailSender).send(any(MimeMessage.class));
        verify(templateEngine).process(eq("email/contact-form"), any(Context.class));
    }

    @Test
    void sendContactFormEmail_WithNullRecipient() throws MessagingException {
        // Given
        String fromEmail = "sender@example.com";
        String subject = "Test Subject";
        String message = "Test Message";
        when(mailSender.createMimeMessage()).thenReturn(mimeMessage);
        when(templateEngine.process(anyString(), any(Context.class))).thenReturn("<html>Email</html>");

        // When
        emailService.sendContactFormEmail(null, fromEmail, subject, message);

        // Then
        verify(mailSender).send(any(MimeMessage.class));
        verify(templateEngine).process(eq("email/contact-form"), any(Context.class));
    }

    @Test
    void sendContactFormEmailAsync_ReturnsCompletableFuture() throws ExecutionException, InterruptedException, TimeoutException {
        // Given
        String fromEmail = "sender@example.com";
        String subject = "Test Subject";
        String message = "Test Message";
        when(mailSender.createMimeMessage()).thenReturn(mimeMessage);
        when(templateEngine.process(anyString(), any(Context.class))).thenReturn("<html>Email</html>");
        // Use doNothing() for void methods when mocking async behavior
        doNothing().when(mailSender).send(any(MimeMessage.class));

        // When
        CompletableFuture<Void> future = emailService.sendContactFormEmailAsync(fromEmail, subject, message);

        // Then
        assertNotNull(future);

        // Wait for the future to complete
        future.get(5, TimeUnit.SECONDS);

        assertFalse(future.isCompletedExceptionally());

        // Verify interactions happened within the async task
        verify(mailSender).send(any(MimeMessage.class));
        verify(templateEngine).process(eq("email/contact-form"), any(Context.class));
    }

    @Test
    void buildVerificationUrl_WithLocalhost() {
        // Given
        String token = "test-token";

        // When
        String url = ReflectionTestUtils.invokeMethod(emailService, "buildVerificationUrl", token);

        // Then
        assertEquals("http://localhost:8081/api/v1/verification/verify/test-token", url);
    }

    @Test
    void buildVerificationUrl_WithCustomServiceUrl() {
        // Given
        String token = "test-token";
        ReflectionTestUtils.setField(emailService, "serviceUrl", "https://api.example.com");

        // When
        String url = ReflectionTestUtils.invokeMethod(emailService, "buildVerificationUrl", token);

        // Then
        assertEquals("https://api.example.com/api/v1/verification/verify/test-token", url);
    }

    @Test
    void buildVerificationUrl_WithTrailingSlash() {
        // Given
        String token = "test-token";
        ReflectionTestUtils.setField(emailService, "serviceUrl", "https://api.example.com/");

        // When
        String url = ReflectionTestUtils.invokeMethod(emailService, "buildVerificationUrl", token);

        // Then
        assertEquals("https://api.example.com/api/v1/verification/verify/test-token", url);
    }
}
