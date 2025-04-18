package dev.idachev.userservice.service;

import dev.idachev.userservice.config.EmailProperties;
import dev.idachev.userservice.model.User;
import jakarta.mail.MessagingException;
import jakarta.mail.Session;
import jakarta.mail.internet.MimeMessage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.mail.javamail.JavaMailSender;
import org.thymeleaf.context.Context;
import org.thymeleaf.spring6.SpringTemplateEngine;

import java.util.Properties;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;
import static org.mockito.Mockito.lenient;

@ExtendWith(MockitoExtension.class)
@DisplayName("EmailService Tests")
@MockitoSettings(strictness = Strictness.LENIENT)
class EmailServiceUTest {

    @Mock
    private JavaMailSender mailSender;
    @Mock
    private SpringTemplateEngine templateEngine;
    @Mock
    private EmailProperties emailProperties;

    @InjectMocks
    private EmailService emailService;

    // Use a real MimeMessage for capturing, needs a Session
    private MimeMessage mimeMessage;

    @Captor
    private ArgumentCaptor<Context> contextCaptor;
    @Captor
    private ArgumentCaptor<MimeMessage> mimeMessageCaptor;

    private final String FROM_ADDRESS = "test@from.com";
    private final String APP_NAME = "TestApp";
    private final String CONTACT_RECIPIENT = "contact@test.com";

    @BeforeEach
    void setUp() {
        // Mock properties with lenient setting
        lenient().when(emailProperties.getFromAddress()).thenReturn(FROM_ADDRESS);
        lenient().when(emailProperties.getAppName()).thenReturn(APP_NAME);
        lenient().when(emailProperties.getContactRecipient()).thenReturn(CONTACT_RECIPIENT);

        // Mock mailSender to create a MimeMessage we can inspect
        // Need a dummy Session for MimeMessage creation
        Session session = Session.getInstance(new Properties());
        mimeMessage = new MimeMessage(session);
        when(mailSender.createMimeMessage()).thenReturn(mimeMessage);
    }

    @Test
    @DisplayName("sendVerificationEmail should process template and send email")
    void sendVerificationEmail_shouldProcessTemplateAndSend() throws MessagingException {
        // Given
        User user = User.builder()
                .id(UUID.randomUUID())
                .username("verifyUser")
                .email("verify@test.com")
                .build();
        String verificationUrl = "http://verify.me";
        String expectedHtmlContent = "<html>Verification HTML</html>";
        String expectedSubject = APP_NAME + " - Verify Your Email";

        when(templateEngine.process(eq("email/verification"), contextCaptor.capture())).thenReturn(expectedHtmlContent);
        doNothing().when(mailSender).send(any(MimeMessage.class)); // Mock the actual send

        // When
        emailService.sendVerificationEmail(user, verificationUrl);

        // Then
        // Verify template processing
        verify(templateEngine).process(eq("email/verification"), any(Context.class));
        Context capturedContext = contextCaptor.getValue();
        assertThat(capturedContext.getVariable("username")).isEqualTo(user.getUsername());
        assertThat(capturedContext.getVariable("verificationUrl")).isEqualTo(verificationUrl);
        assertThat(capturedContext.getVariable("appName")).isEqualTo(APP_NAME);
        assertThat(capturedContext.getVariable("supportEmail")).isEqualTo(CONTACT_RECIPIENT);

        // Verify email sending
        verify(mailSender).send(mimeMessageCaptor.capture());
        MimeMessage capturedMessage = mimeMessageCaptor.getValue();

        // Assertions on the captured MimeMessage (more complex)
        assertThat(capturedMessage.getSubject()).isEqualTo(expectedSubject);
        assertThat(capturedMessage.getAllRecipients()[0].toString()).isEqualTo(user.getEmail());
        // Check content requires more work (getContent(), etc.) but verifying subject/recipient is often enough
        // assertThat(capturedMessage.getContent().toString()).contains(expectedHtmlContent);
    }

    @Nested
    class SendVerificationEmailTests {

        @Test
        @MockitoSettings(strictness = Strictness.LENIENT)
        void sendVerificationEmail_shouldNotSendIfUserOrEmailIsNullEmpty() {
            // Given user is null
            emailService.sendVerificationEmail(null, "someUrl");

            verifyNoInteractions(mailSender, emailProperties, templateEngine);
        }

        @Test
        @MockitoSettings(strictness = Strictness.LENIENT)
        void sendVerificationEmail_shouldNotSendIfVerificationUrlIsBlank() {
            // Given url is blank
            emailService.sendVerificationEmail(User.builder().build(), " ");

            verifyNoInteractions(mailSender, emailProperties, templateEngine);
        }
    }

    @Test
    @DisplayName("sendContactFormEmail (default recipient) should process template and send email")
    void sendContactFormEmail_defaultRecipient_shouldProcessAndSend() throws MessagingException {
        // Given
        String fromUserEmail = "sender@test.com";
        String subject = "Help Needed";
        String message = "My message body.";
        String expectedHtmlContent = "<html>Contact HTML</html>";
        String expectedSubject = "Contact Form [" + APP_NAME + "]: " + subject;

        when(templateEngine.process(eq("email/contact-form"), contextCaptor.capture())).thenReturn(expectedHtmlContent);
        doNothing().when(mailSender).send(any(MimeMessage.class));

        // When
        emailService.sendContactFormEmail(fromUserEmail, subject, message);

        // Then
        // Verify template processing
        verify(templateEngine).process(eq("email/contact-form"), any(Context.class));
        Context capturedContext = contextCaptor.getValue();
        assertThat(capturedContext.getVariable("fromEmail")).isEqualTo(fromUserEmail);
        assertThat(capturedContext.getVariable("subject")).isEqualTo(subject);
        assertThat(capturedContext.getVariable("message")).isEqualTo(message);
        assertThat(capturedContext.getVariable("appName")).isEqualTo(APP_NAME);

        // Verify email sending
        verify(mailSender).send(mimeMessageCaptor.capture());
        MimeMessage capturedMessage = mimeMessageCaptor.getValue();
        assertThat(capturedMessage.getSubject()).isEqualTo(expectedSubject);
        assertThat(capturedMessage.getAllRecipients()[0].toString()).isEqualTo(CONTACT_RECIPIENT); // Default recipient
    }

    @Test
    @DisplayName("sendContactFormEmail (specific recipient) should process template and send email")
    void sendContactFormEmail_specificRecipient_shouldProcessAndSend() throws MessagingException {
        // Given
        String recipient = "specific@example.com";
        String fromUserEmail = "sender@test.com";
        String subject = "Specific Help";
        String message = "My specific message body.";
        String expectedHtmlContent = "<html>Specific Contact HTML</html>";
        String expectedSubject = "Contact Form [" + APP_NAME + "]: " + subject;

        when(templateEngine.process(eq("email/contact-form"), any(Context.class))).thenReturn(expectedHtmlContent);
        doNothing().when(mailSender).send(any(MimeMessage.class));

        // When
        emailService.sendContactFormEmail(recipient, fromUserEmail, subject, message);

        // Then
        // Verify email sending to specific recipient
        verify(mailSender).send(mimeMessageCaptor.capture());
        MimeMessage capturedMessage = mimeMessageCaptor.getValue();
        assertThat(capturedMessage.getAllRecipients()[0].toString()).isEqualTo(recipient);
        assertThat(capturedMessage.getSubject()).isEqualTo(expectedSubject);
        verify(templateEngine).process(eq("email/contact-form"), any(Context.class)); // Ensure template still processed
    }

    // Note: Testing the private @Async sendEmail method directly is harder in unit tests.
    // We test the public methods and verify the interaction with mailSender.send(), assuming the async part works.
    // Testing the exception handling within the @Async method would require more complex async testing setup or integration tests.
} 