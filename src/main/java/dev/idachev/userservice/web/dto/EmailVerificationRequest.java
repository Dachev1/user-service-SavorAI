package dev.idachev.userservice.web.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Data Transfer Object for email verification requests
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Email verification request parameters")
public class EmailVerificationRequest {
    
    @NotBlank(message = "Email cannot be empty")
    @Email(message = "Email must be valid")
    @Schema(description = "User's email address", example = "john.doe@example.com")
    private String email;
} 