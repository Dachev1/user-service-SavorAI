package dev.idachev.userservice.service;

import dev.idachev.userservice.model.User;
import jakarta.mail.internet.MimeMessage;
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
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
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

    @Test
    void whenGenerateVerificationToken_thenReturnUUID() {

        //When
        String token = emailService.generateVerificationToken();

        // Then
        assertNotNull(token);
        assertDoesNotThrow(() -> UUID.fromString(token)); // verify it's a valid UUID
    }

    @Test
    void givenNullUser_whenSendVerificationEmail_thenThrowIllegalArgumentException() {

        // When & Then
        assertThrows(IllegalArgumentException.class, () -> emailService.sendVerificationEmail(null));
        verify(mailSender, never()).createMimeMessage();
        verify(templateEngine, never()).process(anyString(), any(Context.class));
    }

    @Test
    void givenUserWithEmptyEmail_whenSendVerificationEmail_thenThrowIllegalArgumentException() {

        //Given
        User user = User.builder()
                .username("TestUser")
                .verificationToken(UUID.randomUUID().toString())
                .build();

        // When & Then
        assertThrows(IllegalArgumentException.class, () -> emailService.sendVerificationEmail(user));
        verify(mailSender, never()).createMimeMessage();
        verify(templateEngine, never()).process(anyString(), any(Context.class));
    }

    @Test
    void givenValidUser_whenSendVerificationEmail_thenProcessTemplateAndSendEmail() {

        // Given
        User user = User.builder()
                .email("test@example.com")
                .username("TestUser")
                .verificationToken(UUID.randomUUID().toString())
                .build();

        // Set up ReflectionTestUtils to set private fields
        ReflectionTestUtils.setField(emailService, "appName", "TestApp");
        ReflectionTestUtils.setField(emailService, "serviceUrl", "http://localhost:8081");

        when(mailSender.createMimeMessage()).thenReturn(mimeMessage);
        when(templateEngine.process(eq("email/verification"), any(Context.class))).thenReturn("<html>Email content</html>");

        // When
        emailService.sendVerificationEmail(user);

        // Then
        verify(mailSender).createMimeMessage();
        verify(templateEngine).process(eq("email/verification"), any(Context.class));
        verify(mailSender).send(mimeMessage);
    }

    @Test
    void givenNullEmail_whenSendVerificationEmailDirectly_thenThrowIllegalArgumentException() {

        // When & Then
        assertThrows(IllegalArgumentException.class,
                () -> emailService.sendVerificationEmail(null, "TestUser", UUID.randomUUID().toString()));
        verify(mailSender, never()).createMimeMessage();
    }

    @Test
    void givenNullToken_whenSendVerificationEmailDirectly_thenThrowIllegalArgumentException() {

        // When & Then
        assertThrows(IllegalArgumentException.class,
                () -> emailService.sendVerificationEmail("test@example.com", "TestUser", null));
        verify(mailSender, never()).createMimeMessage();
    }

    @Test
    void givenValidParams_whenSendVerificationEmailDirectly_thenProcessTemplateAndSendEmail() {

        // Given
        String email = "test@example.com";
        String username = "TestUser";
        String token = UUID.randomUUID().toString();

        // Set up ReflectionTestUtils to set private fields
        ReflectionTestUtils.setField(emailService, "appName", "TestApp");
        ReflectionTestUtils.setField(emailService, "serviceUrl", "http://localhost:8081");

        when(mailSender.createMimeMessage()).thenReturn(mimeMessage);
        when(templateEngine.process(eq("email/verification"), any(Context.class))).thenReturn("<html>Email content</html>");

        // When
        emailService.sendVerificationEmail(email, username, token);

        // Then
        verify(mailSender).createMimeMessage();
        verify(templateEngine).process(eq("email/verification"), any(Context.class));
        verify(mailSender).send(mimeMessage);
    }

    @Test
    void givenValidUser_whenSendVerificationEmailAsync_thenReturnCompletableFuture() throws ExecutionException, InterruptedException, TimeoutException {

        // Given
        User user = User.builder()
                .email("test@example.com")
                .username("testuser")
                .verificationToken("token123")
                .build();

        // Set up ReflectionTestUtils to set private fields
        ReflectionTestUtils.setField(emailService, "appName", "TestApp");
        ReflectionTestUtils.setField(emailService, "serviceUrl", "http://localhost:8081");

        when(mailSender.createMimeMessage()).thenReturn(mimeMessage);
        when(templateEngine.process(eq("email/verification"), any(Context.class))).thenReturn("<html>Email content</html>");

        // When
        CompletableFuture<Void> future = emailService.sendVerificationEmailAsync(user);

        // Then
        assertNotNull(future);
        // Wait for async operation to complete
        future.get(1, TimeUnit.SECONDS);
        verify(mailSender).createMimeMessage();
        verify(templateEngine).process(eq("email/verification"), any(Context.class));
        verify(mailSender).send(mimeMessage);
    }

    @Test
    void givenNullUser_whenSendVerificationEmailAsync_thenHandleErrorGracefully() throws ExecutionException, InterruptedException, TimeoutException {

        // When
        CompletableFuture<Void> future = emailService.sendVerificationEmailAsync(null);

        // Then
        assertNotNull(future);

        // Wait for async operation to complete
        future.get(1, TimeUnit.SECONDS);
        verify(mailSender, never()).createMimeMessage();
        verify(templateEngine, never()).process(anyString(), any(Context.class));
    }

    @Test
    void whenBuildVerificationUrl_thenReturnProperUrl() {
        // Given
        String token = "test-token";
        ReflectionTestUtils.setField(emailService, "serviceUrl", "http://localhost");
        ReflectionTestUtils.setField(emailService, "serverPort", "8081");

        // Use reflection to access the private method
        String url = ReflectionTestUtils.invokeMethod(emailService, "buildVerificationUrl", token);

        // Then
        assertNotNull(url);
        assertTrue(url.contains(token), "URL should contain the token");
        assertTrue(url.startsWith("http://localhost:8081"), "URL should start with serviceUrl+port");
        assertTrue(url.contains("/api/v1/verification/verify/"), "URL should contain the verification path");
        assertEquals("http://localhost:8081/api/v1/verification/verify/test-token", url, "URL should be correctly formatted");
    }
}
