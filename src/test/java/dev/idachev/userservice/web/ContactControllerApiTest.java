package dev.idachev.userservice.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.idachev.userservice.security.JwtAuthenticationFilter;
import dev.idachev.userservice.service.EmailService;
import dev.idachev.userservice.web.dto.ContactFormRequest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.FilterType;
import org.springframework.http.MediaType;
import org.springframework.mail.MailSendException;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.then;
import static org.mockito.BDDMockito.willThrow;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(controllers = ContactController.class,
        excludeAutoConfiguration = SecurityAutoConfiguration.class,
        excludeFilters = {
                @ComponentScan.Filter(type = FilterType.ASSIGNABLE_TYPE, classes = JwtAuthenticationFilter.class)
        }
)
@DisplayName("ContactController Tests")
class ContactControllerApiTest {

    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private ObjectMapper objectMapper;
    @MockitoBean
    private EmailService emailService;

    @Test
    @DisplayName("POST /submit - Success")
    void submitContactForm_Success() throws Exception {
        ContactFormRequest request = ContactFormRequest.builder()
                .email("test@example.com")
                .subject("Test Subject")
                .message("This is a test message.")
                .build();

        mockMvc.perform(post("/api/v1/contact/submit")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.message").value("Thank you for your message. We will get back to you soon."));

        then(emailService).should().sendContactFormEmail(
                eq(request.getEmail()),
                eq(request.getSubject()),
                eq(request.getMessage())
        );
    }

    @Test
    @DisplayName("POST /submit - Failure (Email Sending Error)")
    void submitContactForm_Failure_EmailError() throws Exception {
        ContactFormRequest request = ContactFormRequest.builder()
                .email("test@example.com")
                .subject("Test Subject")
                .message("This is a test message.")
                .build();

        willThrow(new MailSendException("Failed to send email"))
                .given(emailService).sendContactFormEmail(anyString(), anyString(), anyString());

        mockMvc.perform(post("/api/v1/contact/submit")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isInternalServerError());
    }

    @Test
    @DisplayName("POST /submit - Failure (Validation Error)")
    void submitContactForm_Failure_ValidationError() throws Exception {
        // Invalid request: blank email
        ContactFormRequest request = ContactFormRequest.builder()
                .email(" ") // Invalid: blank email
                .subject("Valid Subject")
                .message("Valid message content here.")
                .build();

        mockMvc.perform(post("/api/v1/contact/submit")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest()); // Expect 400 due to @Valid failure
    }
} 