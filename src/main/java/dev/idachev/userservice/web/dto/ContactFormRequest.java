package dev.idachev.userservice.web.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Data Transfer Object for contact form submissions
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Contact form submission request")
public class ContactFormRequest {

    @Email(message = "Email must be valid")
    @NotBlank(message = "Email cannot be empty")
    @Schema(description = "Email address of the sender", example = "user@example.com")
    private String email;

    @NotBlank(message = "Subject cannot be empty")
    @Schema(description = "Subject of the contact message", example = "Question about services")
    private String subject;

    @NotBlank(message = "Message cannot be empty")
    @Schema(description = "Content of the contact message", example = "I have a question about your services...")
    private String message;
} 