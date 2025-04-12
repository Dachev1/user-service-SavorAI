package dev.idachev.userservice.web.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
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
    @Size(max = 100, message = "Email cannot exceed 100 characters")
    @Pattern(regexp = "^[\\w-\\.]+@([\\w-]+\\.)+[\\w-]{2,}$", message = "Email format is invalid")
    @Schema(description = "Email address of the sender", example = "user@example.com")
    private String email;

    @NotBlank(message = "Subject cannot be empty")
    @Size(min = 3, max = 100, message = "Subject must be between 3 and 100 characters")
    @Pattern(regexp = "^[\\p{L}\\p{N}\\s.,!?-]+$", message = "Subject contains invalid characters")
    @Schema(description = "Subject of the contact message", example = "Question about services")
    private String subject;

    @NotBlank(message = "Message cannot be empty")
    @Size(min = 10, max = 1000, message = "Message must be between 10 and 1000 characters")
    @Schema(description = "Content of the contact message", example = "I have a question about your services...")
    private String message;
} 