package dev.idachev.userservice.integration;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.idachev.userservice.service.EmailService;
import dev.idachev.userservice.service.TokenBlacklistService;
import dev.idachev.userservice.web.dto.ContactFormRequest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Transactional // Although this controller doesn't interact with DB directly, keep it for consistency
class ContactITest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    // Mock the EmailService as we don't want to send actual emails during integration tests
    @MockitoBean
    private EmailService emailService;

    // Mock TokenBlacklistService to satisfy context creation (even if not used directly)
    @MockitoBean
    private TokenBlacklistService tokenBlacklistService;

    // --- Submit Contact Form Tests ---

    @Test
    void givenValidContactForm_whenSubmit_thenOkAndEmailServiceCalled() throws Exception {
        // Given: Valid contact form request
        ContactFormRequest request = ContactFormRequest.builder()
                .email("test.sender@example.com")
                .subject("Valid Subject Line")
                .message("This is a valid message body with more than ten characters.")
                .build();

        // And given: Mock EmailService configuration
        doNothing().when(emailService).sendContactFormEmail(anyString(), anyString(), anyString());

        // When: Submit endpoint is called
        mockMvc.perform(post("/api/v1/contact/submit")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                // Then: Response is OK
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.message").value("Thank you for your message. We will get back to you soon."));

        // And then: Verify EmailService called correctly
        verify(emailService).sendContactFormEmail(
                request.getEmail(),
                request.getSubject(),
                request.getMessage()
        );
    }

    @Test
    void givenInvalidEmailFormat_whenSubmit_thenBadRequest() throws Exception {
        // Given: Request with invalid email
        ContactFormRequest request = ContactFormRequest.builder()
                .email("invalid-email")
                .subject("Valid Subject")
                .message("This is a valid message body.")
                .build();

        // When: Submit endpoint is called
        mockMvc.perform(post("/api/v1/contact/submit")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                // Then: Response is 400 Bad Request
                .andExpect(status().isBadRequest());
    }

    @Test
    void givenBlankSubject_whenSubmit_thenBadRequest() throws Exception {
        // Given: Request with blank subject
        ContactFormRequest request = ContactFormRequest.builder()
                .email("test.sender@example.com")
                .subject("") // Blank subject
                .message("This is a valid message body.")
                .build();

        // When: Submit endpoint is called
        mockMvc.perform(post("/api/v1/contact/submit")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                // Then: Response is 400 Bad Request
                .andExpect(status().isBadRequest());
    }

    @Test
    void givenShortMessage_whenSubmit_thenBadRequest() throws Exception {
        // Given: Request with short message
        ContactFormRequest request = ContactFormRequest.builder()
                .email("test.sender@example.com")
                .subject("Valid Subject")
                .message("Too short") // Message less than 10 chars
                .build();

        // When: Submit endpoint is called
        mockMvc.perform(post("/api/v1/contact/submit")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                // Then: Response is 400 Bad Request
                .andExpect(status().isBadRequest());
    }

    // TODO: Add test for case where EmailService throws an exception (expect 500 Internal Server Error)

} 