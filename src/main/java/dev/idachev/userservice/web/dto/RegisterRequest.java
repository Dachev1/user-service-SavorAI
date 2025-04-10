package dev.idachev.userservice.web.dto;

import dev.idachev.userservice.validation.PasswordValidator;
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
 * Data Transfer Object for user registration requests
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Request payload for user registration")
public class RegisterRequest {

    @NotBlank(message = "Username cannot be empty")
    @Size(min = 3, max = 50, message = "Username must be between 3 and 50 characters")
    @Pattern(regexp = "^[a-zA-Z0-9._-]+$", message = "Username can only contain letters, numbers, dots, underscores, and hyphens")
    @Schema(description = "User's username (3-50 characters)", example = "johndoe")
    private String username;

    @NotBlank(message = "Email cannot be empty")
    @Email(message = "Email must be valid")
    @Size(max = 100, message = "Email must not exceed 100 characters")
    @Schema(description = "User's email address", example = "john.doe@example.com")
    private String email;

    @NotBlank(message = "Password cannot be empty")
    @PasswordValidator
    @Schema(description = "User's password (min 8 characters with at least one uppercase letter, one lowercase letter, one digit, and one special character)", 
            example = "Password123!")
    private String password;
} 