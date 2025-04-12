package dev.idachev.userservice.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.idachev.userservice.config.TestSecurityConfig;
import dev.idachev.userservice.service.EmailService;
import dev.idachev.userservice.web.dto.ContactFormRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.util.concurrent.CompletableFuture;

import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(controllers = ContactController.class)
@AutoConfigureMockMvc(addFilters = false)
@Import(TestSecurityConfig.class)
public class ContactControllerApiTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockitoBean
    private EmailService emailService;

    private ContactFormRequest validRequest;

    @BeforeEach
    void setUp() {
        validRequest = ContactFormRequest.builder()
                .email("test@example.com")
                .subject("Test Subject")
                .message("Test Message")
                .build();
    }

    @Test
    public void submitContactForm_WhenValidRequest_ReturnsSuccess() throws Exception {
        // Given
        when(emailService.sendContactFormEmailAsync(
                eq(validRequest.getEmail()),
                eq(validRequest.getSubject()),
                eq(validRequest.getMessage())
        )).thenReturn(CompletableFuture.completedFuture(null));

        // When/Then
        mockMvc.perform(post("/api/v1/contact/submit")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(validRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success", is(true)));

        verify(emailService).sendContactFormEmailAsync(
                eq(validRequest.getEmail()),
                eq(validRequest.getSubject()),
                eq(validRequest.getMessage())
        );
    }

    @Test
    public void submitContactForm_WhenInvalidEmail_ReturnsBadRequest() throws Exception {
        // Given
        ContactFormRequest invalidRequest = ContactFormRequest.builder()
                .email("invalid-email")
                .subject("Test Subject")
                .message("Test Message")
                .build();

        // When/Then
        mockMvc.perform(post("/api/v1/contact/submit")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(invalidRequest)))
                .andExpect(status().isBadRequest());

        verify(emailService, never()).sendContactFormEmailAsync(anyString(), anyString(), anyString());
    }

    @Test
    public void submitContactForm_WhenEmptySubject_ReturnsBadRequest() throws Exception {
        // Given
        ContactFormRequest invalidRequest = ContactFormRequest.builder()
                .email("test@example.com")
                .subject("")
                .message("Test Message")
                .build();

        // When/Then
        mockMvc.perform(post("/api/v1/contact/submit")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(invalidRequest)))
                .andExpect(status().isBadRequest());

        verify(emailService, never()).sendContactFormEmailAsync(anyString(), anyString(), anyString());
    }

    @Test
    public void submitContactForm_WhenEmptyMessage_ReturnsBadRequest() throws Exception {
        // Given
        ContactFormRequest invalidRequest = ContactFormRequest.builder()
                .email("test@example.com")
                .subject("Test Subject")
                .message("")
                .build();

        // When/Then
        mockMvc.perform(post("/api/v1/contact/submit")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(invalidRequest)))
                .andExpect(status().isBadRequest());

        verify(emailService, never()).sendContactFormEmailAsync(anyString(), anyString(), anyString());
    }

    @Test
    public void submitContactForm_WhenEmailServiceFails_ReturnsInternalServerError() throws Exception {
        // Given
        doThrow(new RuntimeException("Email service error"))
                .when(emailService)
                .sendContactFormEmailAsync(
                        eq(validRequest.getEmail()),
                        eq(validRequest.getSubject()),
                        eq(validRequest.getMessage())
                );

        // When/Then
        mockMvc.perform(post("/api/v1/contact/submit")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(validRequest)))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.success", is(false)));

        verify(emailService).sendContactFormEmailAsync(
                eq(validRequest.getEmail()),
                eq(validRequest.getSubject()),
                eq(validRequest.getMessage())
        );
    }
} 