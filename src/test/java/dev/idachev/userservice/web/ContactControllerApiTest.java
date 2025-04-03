package dev.idachev.userservice.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.idachev.userservice.config.JwtConfig;
import dev.idachev.userservice.repository.UserRepository;
import dev.idachev.userservice.service.EmailService;
import dev.idachev.userservice.service.TokenBlacklistService;
import dev.idachev.userservice.service.UserDetailsService;
import dev.idachev.userservice.web.dto.ContactRequest;
import dev.idachev.userservice.web.dto.GenericResponse;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.cache.CacheManager;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import java.util.concurrent.CompletableFuture;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
class ContactControllerApiTest {

    @MockitoBean
    private EmailService emailService;

    @MockitoBean
    private JwtConfig jwtConfig;

    @MockitoBean
    private TokenBlacklistService tokenBlacklistService;

    @MockitoBean
    private AuthenticationManager authenticationManager;

    @MockitoBean
    private UserDetailsService userDetailsService;

    @MockitoBean
    private UserRepository userRepository;

    @MockitoBean
    private CacheManager cacheManager;

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    private static final String CONTACT_SUBMIT_URL = "/api/v1/contact/submit";

    @Test
    void submitContactForm_ValidRequest_ShouldReturnOkResponse() throws Exception {

        // Given
        String email = "user@example.com";
        String subject = "Test Subject";
        String message = "Test message content";

        ContactRequest request = new ContactRequest();
        request.setEmail(email);
        request.setSubject(subject);
        request.setMessage(message);

        when(emailService.sendContactFormEmailAsync(eq(email), eq(subject), eq(message)))
                .thenReturn(CompletableFuture.completedFuture(null));

        // When
        MockHttpServletRequestBuilder requestBuilder = post(CONTACT_SUBMIT_URL)
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request));

        // Then
        MvcResult result = mockMvc.perform(requestBuilder)
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.status").value(200))
                .andExpect(jsonPath("$.message").exists())
                .andExpect(jsonPath("$.timestamp").exists())
                .andReturn();

        GenericResponse response = objectMapper.readValue(
                result.getResponse().getContentAsString(),
                GenericResponse.class);

        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getMessage()).contains("Thank you");
        verify(emailService).sendContactFormEmailAsync(email, subject, message);
    }

    @Test
    void submitContactForm_InvalidEmail_ShouldReturnBadRequest() throws Exception {

        // Given
        ContactRequest request = new ContactRequest();
        request.setEmail("invalid-email");
        request.setSubject("Test Subject");
        request.setMessage("Test message content");

        // When
        MockHttpServletRequestBuilder requestBuilder = post(CONTACT_SUBMIT_URL)
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request));

        // Then
        mockMvc.perform(requestBuilder)
                .andExpect(status().isBadRequest());

        verifyNoInteractions(emailService);
    }

    @Test
    void submitContactForm_EmptySubject_ShouldReturnBadRequest() throws Exception {

        // Given
        ContactRequest request = new ContactRequest();
        request.setEmail("user@example.com");
        request.setSubject("");
        request.setMessage("Test message content");

        // When
        MockHttpServletRequestBuilder requestBuilder = post(CONTACT_SUBMIT_URL)
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request));

        // Then
        mockMvc.perform(requestBuilder)
                .andExpect(status().isBadRequest());

        verifyNoInteractions(emailService);
    }

    @Test
    void submitContactForm_EmptyMessage_ShouldReturnBadRequest() throws Exception {

        // Given
        ContactRequest request = new ContactRequest();
        request.setEmail("user@example.com");
        request.setSubject("Test Subject");
        request.setMessage("");

        // When
        MockHttpServletRequestBuilder requestBuilder = post(CONTACT_SUBMIT_URL)
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request));

        // Then
        mockMvc.perform(requestBuilder)
                .andExpect(status().isBadRequest());

        verifyNoInteractions(emailService);
    }

    @Test
    void submitContactForm_ServiceThrowsException_ShouldReturnInternalServerError() throws Exception {

        // Given
        String email = "user@example.com";
        String subject = "Test Subject";
        String message = "Test message content";

        ContactRequest request = new ContactRequest();
        request.setEmail(email);
        request.setSubject(subject);
        request.setMessage(message);

        doThrow(new RuntimeException("Test exception"))
                .when(emailService).sendContactFormEmailAsync(anyString(), anyString(), anyString());

        // When
        MockHttpServletRequestBuilder requestBuilder = post(CONTACT_SUBMIT_URL)
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request));

        // Then
        MvcResult result = mockMvc.perform(requestBuilder)
                .andExpect(status().isInternalServerError())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.status").value(500))
                .andExpect(jsonPath("$.message").exists())
                .andReturn();

        GenericResponse response = objectMapper.readValue(
                result.getResponse().getContentAsString(),
                GenericResponse.class);

        assertThat(response.getStatus()).isEqualTo(500);
        assertThat(response.getMessage()).contains("Failed");
        verify(emailService).sendContactFormEmailAsync(email, subject, message);
    }
} 