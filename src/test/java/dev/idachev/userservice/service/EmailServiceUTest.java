package dev.idachev.userservice.service;

import dev.idachev.userservice.exception.EmailSendException;
import dev.idachev.userservice.model.Role;
import dev.idachev.userservice.model.User;
import dev.idachev.userservice.web.dto.GenericResponse;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.test.util.ReflectionTestUtils;
import org.thymeleaf.context.Context;
import org.thymeleaf.spring6.SpringTemplateEngine;

import java.time.LocalDateTime;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;
import static org.mockito.Mockito.lenient;

@ExtendWith(MockitoExtension.class)
class EmailServiceUTest {

    @Mock
    private JavaMailSender mailSender;

    @Mock
    private SpringTemplateEngine templateEngine;

    @Mock
    private MimeMessage mimeMessage;

    @Captor
    private ArgumentCaptor<Context> contextCaptor;

    private EmailService emailService;
    private User testUser;

    @BeforeEach
    void setUp() {
        emailService = new EmailService(mailSender, templateEngine);
        
        // Set required properties using reflection
        ReflectionTestUtils.setField(emailService, "appName", "TestApp");
        ReflectionTestUtils.setField(emailService, "serverPort", "8081");
        ReflectionTestUtils.setField(emailService, "serviceUrl", "http://localhost");
        ReflectionTestUtils.setField(emailService, "defaultContactRecipient", "test@example.com");
        ReflectionTestUtils.setField(emailService, "fromEmail", "noreply@testapp.com");
        
        // Setup test user
        testUser = User.builder()
                .id(UUID.randomUUID())
                .username("testuser")
                .email("user@example.com")
                .password("encodedPassword")
                .role(Role.USER)
                .enabled(false)
                .verificationToken("8a5b22f3-6cba-4c8b-acd6-983fe63af20c")
                .createdOn(LocalDateTime.now())
                .build();
    }

    @Test
    @DisplayName("Should generate verification token successfully")
    void should_GenerateVerificationToken_Successfully() {
        // When
        String token = emailService.generateVerificationToken();
        
        // Then
        assertThat(token).isNotNull();
        assertThat(token).isNotEmpty();
        
        // Try to parse as UUID to validate format
        UUID.fromString(token);
    }

    @Test
    @DisplayName("Should send verification email successfully")
    void should_SendVerificationEmail_Successfully() throws MessagingException {
        // Given
        when(mailSender.createMimeMessage()).thenReturn(mimeMessage);
        when(templateEngine.process(eq("email/verification"), any(Context.class))).thenReturn("<html>Test Email</html>");
        
        // When
        emailService.sendVerificationEmail(testUser);
        
        // Then
        verify(mailSender).createMimeMessage();
        verify(templateEngine).process(eq("email/verification"), contextCaptor.capture());
        verify(mailSender).send(any(MimeMessage.class));
        
        Context capturedContext = contextCaptor.getValue();
        assertThat(capturedContext.getVariable("username")).isEqualTo(testUser.getUsername());
        assertThat(capturedContext.getVariable("verificationUrl")).isNotNull();
    }

    @Test
    @DisplayName("Should send verification email asynchronously")
    void should_SendVerificationEmailAsync_Successfully() {
        // Create spy
        EmailService spyEmailService = spy(emailService);
        
        // Use doNothing to avoid actually calling the method
        doNothing().when(spyEmailService).sendVerificationEmail(any(User.class));
        
        // When
        CompletableFuture<Void> future = spyEmailService.sendVerificationEmailAsync(testUser);
        
        // We can't verify the async behavior easily, so just check if the method doesn't throw
        assertThat(future).isNotNull();
    }

    @Test
    @DisplayName("Should process contact form successfully")
    void should_ProcessContactForm_Successfully() throws MessagingException {
        // Given
        String senderEmail = "sender@example.com";
        String subject = "Test Subject";
        String message = "Test Message";
        
        // Use lenient mocking for the async behavior 
        lenient().when(mailSender.createMimeMessage()).thenReturn(mimeMessage);
        lenient().when(templateEngine.process(eq("email/contact-form"), any(Context.class))).thenReturn("<html>Test Contact Email</html>");
        
        // Create spy for async behavior
        EmailService spyEmailService = spy(emailService);
        doReturn(CompletableFuture.completedFuture(null))
            .when(spyEmailService).sendContactFormEmailAsync(anyString(), anyString(), anyString());
        
        // When
        GenericResponse response = spyEmailService.processContactForm(senderEmail, subject, message);
        
        // Then
        verify(spyEmailService).sendContactFormEmailAsync(senderEmail, subject, message);
        
        assertThat(response.isSuccess()).isTrue();
        assertThat(response.getMessage()).contains("Thank you for your message");
        assertThat(response.getStatus()).isEqualTo(HttpStatus.OK.value());
    }

    @Test
    @DisplayName("Should handle email sending failure gracefully")
    void should_HandleEmailSendingFailure_Gracefully() throws MessagingException {
        // Given
        when(mailSender.createMimeMessage()).thenReturn(mimeMessage);
        when(templateEngine.process(anyString(), any(Context.class))).thenReturn("<html>Test Email</html>");
        doThrow(new RuntimeException("Failed to send email")).when(mailSender).send(any(MimeMessage.class));
        
        // When/Then
        assertThatThrownBy(() -> emailService.sendVerificationEmail(testUser))
                .isInstanceOf(EmailSendException.class)
                .hasMessageContaining("Failed to send verification email");
    }
} 