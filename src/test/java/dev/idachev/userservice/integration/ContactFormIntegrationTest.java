package dev.idachev.userservice.integration;

import dev.idachev.userservice.web.dto.ContactFormRequest;
import dev.idachev.userservice.web.dto.GenericResponse;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.ActiveProfiles;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
class ContactFormIntegrationTest {

    @Autowired
    private TestRestTemplate restTemplate;

    @Test
    @DisplayName("Should submit contact form successfully")
    void should_SubmitContactForm_Successfully() {
        // Given
        ContactFormRequest request = new ContactFormRequest(
                "test@example.com",
                "Test Subject",
                "This is a test message for the contact form integration test."
        );

        // When
        ResponseEntity<GenericResponse> response = restTemplate.postForEntity(
                "/api/v1/contact/submit",
                request,
                GenericResponse.class
        );

        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().isSuccess()).isTrue();
        assertThat(response.getBody().getMessage()).isEqualTo("Thank you for your message. We'll get back to you soon!");
    }

    @Test
    @DisplayName("Should reject contact form with invalid email")
    void should_RejectContactForm_WithInvalidEmail() {
        // Given
        ContactFormRequest request = new ContactFormRequest(
                "invalid-email",
                "Test Subject",
                "This is a test message for the contact form integration test."
        );

        // When
        ResponseEntity<Object> response = restTemplate.postForEntity(
                "/api/v1/contact/submit",
                request,
                Object.class
        );

        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    @DisplayName("Should reject contact form with empty subject")
    void should_RejectContactForm_WithEmptySubject() {
        // Given
        ContactFormRequest request = new ContactFormRequest(
                "test@example.com",
                "",
                "This is a test message for the contact form integration test."
        );

        // When
        ResponseEntity<Object> response = restTemplate.postForEntity(
                "/api/v1/contact/submit",
                request,
                Object.class
        );

        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    @DisplayName("Should reject contact form with empty message")
    void should_RejectContactForm_WithEmptyMessage() {
        // Given
        ContactFormRequest request = new ContactFormRequest(
                "test@example.com",
                "Test Subject",
                ""
        );

        // When
        ResponseEntity<Object> response = restTemplate.postForEntity(
                "/api/v1/contact/submit",
                request,
                Object.class
        );

        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }
} 