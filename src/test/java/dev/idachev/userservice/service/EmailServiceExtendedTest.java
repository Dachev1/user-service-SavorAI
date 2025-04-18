package dev.idachev.userservice.service;

import dev.idachev.userservice.exception.EmailSendException;
import dev.idachev.userservice.model.Role;
import dev.idachev.userservice.model.User;
import dev.idachev.userservice.web.dto.GenericResponse;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
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
import java.util.concurrent.ExecutionException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class EmailServiceExtendedTest {

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
        ReflectionTestUtils.setField(emailService, "defaultContactRecipient", "admin@example.com");
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

    @Nested
    @DisplayName("Verification Email Tests")
    class VerificationEmailTests {
        
        @Test
        @DisplayName("Should send verification email with custom parameters")
        void should_SendVerificationEmail_WithCustomParameters() throws MessagingException {
            // Given
            String email = "custom@example.com";
            String username = "customUser";
            String token = "custom-verification-token";
            
            when(mailSender.createMimeMessage()).thenReturn(mimeMessage);
            when(templateEngine.process(eq("email/verification"), any(Context.class))).thenReturn("<html>Test Email</html>");
            
            // When
            emailService.sendVerificationEmail(email, username, token);
            
            // Then
            verify(mailSender).createMimeMessage();
            verify(templateEngine).process(eq("email/verification"), contextCaptor.capture());
            verify(mailSender).send(any(MimeMessage.class));
            
            Context capturedContext = contextCaptor.getValue();
            assertThat(capturedContext.getVariable("username")).isEqualTo(username);
            
            // Verify verification URL contains the custom token
            String verificationUrl = (String) capturedContext.getVariable("verificationUrl");
            assertThat(verificationUrl).contains(token);
        }
        
        @Test
        @DisplayName("Should handle email with null username")
        void should_HandleEmail_WithNullUsername() throws MessagingException {
            // Given
            String email = "user@example.com";
            String token = "verification-token";
            String username = null;
            
            when(mailSender.createMimeMessage()).thenReturn(mimeMessage);
            when(templateEngine.process(eq("email/verification"), any(Context.class))).thenReturn("<html>Test Email</html>");
            
            // When
            emailService.sendVerificationEmail(email, username, token);
            
            // Then
            verify(templateEngine).process(eq("email/verification"), contextCaptor.capture());
            
            Context capturedContext = contextCaptor.getValue();
            assertThat(capturedContext.getVariable("username")).isEqualTo("User"); // Default username
        }
        
        @Test
        @DisplayName("Should await completion of async verification email")
        void should_AwaitCompletion_OfAsyncVerificationEmail() throws ExecutionException, InterruptedException {
            // Create spy to verify behavior
            EmailService spyService = spy(emailService);
            doNothing().when(spyService).sendVerificationEmail(any(User.class));
            
            // When
            CompletableFuture<Void> future = spyService.sendVerificationEmailAsync(testUser);
            
            // Then
            future.get(); // Wait for completion
            verify(spyService).sendVerificationEmail(testUser);
        }
    }
    
    @Nested
    @DisplayName("Contact Form Email Tests")
    class ContactFormEmailTests {
        
        @Test
        @DisplayName("Should send contact form email to default recipient")
        void should_SendContactFormEmail_ToDefaultRecipient() throws MessagingException {
            // Given
            String senderEmail = "sender@example.com";
            String subject = "Test Subject";
            String message = "Test message content";
            
            when(mailSender.createMimeMessage()).thenReturn(mimeMessage);
            when(templateEngine.process(eq("email/contact-form"), any(Context.class))).thenReturn("<html>Test Email</html>");
            
            // When
            emailService.sendContactFormEmail(senderEmail, subject, message);
            
            // Then
            verify(mailSender).createMimeMessage();
            verify(templateEngine).process(eq("email/contact-form"), contextCaptor.capture());
            verify(mailSender).send(any(MimeMessage.class));
            
            Context capturedContext = contextCaptor.getValue();
            assertThat(capturedContext.getVariable("fromEmail")).isEqualTo(senderEmail);
            assertThat(capturedContext.getVariable("subject")).isEqualTo(subject);
            assertThat(capturedContext.getVariable("message")).isEqualTo(message);
        }
        
        @Test
        @DisplayName("Should send contact form email to custom recipient")
        void should_SendContactFormEmail_ToCustomRecipient() throws MessagingException {
            // Given
            String recipient = "custom-recipient@example.com";
            String senderEmail = "sender@example.com";
            String subject = "Test Subject";
            String message = "Test message content";
            
            when(mailSender.createMimeMessage()).thenReturn(mimeMessage);
            when(templateEngine.process(eq("email/contact-form"), any(Context.class))).thenReturn("<html>Test Email</html>");
            
            // When
            emailService.sendContactFormEmail(recipient, senderEmail, subject, message);
            
            // Then
            verify(mailSender).createMimeMessage();
            verify(templateEngine).process(eq("email/contact-form"), any(Context.class));
            
            // Capture the MimeMessageHelper to verify the recipient
            ArgumentCaptor<MimeMessage> mimeMessageCaptor = ArgumentCaptor.forClass(MimeMessage.class);
            verify(mailSender).send(mimeMessageCaptor.capture());
        }
        
        @Test
        @DisplayName("Should await completion of async contact form email")
        void should_AwaitCompletion_OfAsyncContactFormEmail() throws ExecutionException, InterruptedException {
            // Given
            String senderEmail = "sender@example.com";
            String subject = "Test Subject";
            String message = "Test message content";
            
            // Create spy to verify behavior
            EmailService spyService = spy(emailService);
            doNothing().when(spyService).sendContactFormEmail(anyString(), anyString(), anyString());
            
            // When
            CompletableFuture<Void> future = spyService.sendContactFormEmailAsync(senderEmail, subject, message);
            
            // Then
            future.get(); // Wait for completion
            verify(spyService).sendContactFormEmail(senderEmail, subject, message);
        }
        
        @Test
        @DisplayName("Should process contact form and return success response")
        void should_ProcessContactForm_AndReturnSuccessResponse() {
            // Given
            String senderEmail = "sender@example.com";
            String subject = "Test Subject";
            String message = "Test message content";
            
            // Create spy to mock async behavior
            EmailService spyService = spy(emailService);
            doReturn(CompletableFuture.completedFuture(null))
                .when(spyService).sendContactFormEmailAsync(anyString(), anyString(), anyString());
            
            // When
            GenericResponse response = spyService.processContactForm(senderEmail, subject, message);
            
            // Then
            assertThat(response).isNotNull();
            assertThat(response.isSuccess()).isTrue();
            assertThat(response.getMessage()).contains("Thank you");
            assertThat(response.getStatus()).isEqualTo(HttpStatus.OK.value());
            
            verify(spyService).sendContactFormEmailAsync(senderEmail, subject, message);
        }
        
        @Test
        @DisplayName("Should handle exceptions in contact form processing")
        void should_HandleExceptions_InContactFormProcessing() {
            // Given
            String senderEmail = "sender@example.com";
            String subject = "Test Subject";
            String message = "Test message content";
            
            // Create spy to mock exception in async behavior
            EmailService spyService = spy(emailService);
            doThrow(new RuntimeException("Async email failed"))
                .when(spyService).sendContactFormEmailAsync(anyString(), anyString(), anyString());
            
            // When/Then
            assertThatThrownBy(() -> spyService.processContactForm(senderEmail, subject, message))
                .isInstanceOf(EmailSendException.class)
                .hasMessageContaining("Failed to process contact form");
        }
    }
    
    @Nested
    @DisplayName("Helper Method Tests")
    class HelperMethodTests {
        
        @Test
        @DisplayName("Should build correct verification URL")
        void should_BuildCorrectVerificationUrl() throws ReflectiveOperationException {
            // Using reflection to access private method
            java.lang.reflect.Method buildUrlMethod = EmailService.class.getDeclaredMethod("buildVerificationUrl", String.class);
            buildUrlMethod.setAccessible(true);
            
            // When
            String verificationUrl = (String) buildUrlMethod.invoke(emailService, "test-token");
            
            // Then
            assertThat(verificationUrl).isNotNull();
            assertThat(verificationUrl).startsWith("http://localhost:8081");
            assertThat(verificationUrl).contains("test-token");
        }
        
        @Test
        @DisplayName("Should send email with proper format")
        void should_SendEmail_WithProperFormat() throws MessagingException, ReflectiveOperationException {
            // Using reflection to access private method
            java.lang.reflect.Method sendEmailMethod = EmailService.class.getDeclaredMethod(
                "sendEmail", String.class, String.class, String.class);
            sendEmailMethod.setAccessible(true);
            
            // Given
            when(mailSender.createMimeMessage()).thenReturn(mimeMessage);
            
            // When
            sendEmailMethod.invoke(emailService, "recipient@example.com", "Test Subject", "<html>Test Content</html>");
            
            // Then
            verify(mailSender).createMimeMessage();
            verify(mailSender).send(any(MimeMessage.class));
        }
    }
} 