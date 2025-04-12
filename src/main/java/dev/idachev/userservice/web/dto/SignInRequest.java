package dev.idachev.userservice.web.dto;

import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonIgnore;
import dev.idachev.userservice.validation.PasswordValidator;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.*;

/**
 * Data Transfer Object for user sign in requests
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Request payload for user sign in")
public class SignInRequest {

    @NotBlank(message = "Username or email cannot be empty")
    @Size(min = 3, max = 100, message = "Username or email must be between 3 and 100 characters")
    @Schema(description = "User's username or email address", example = "johndoe")
    private String identifier;

    @NotBlank(message = "Password cannot be empty")
    @PasswordValidator
    @Schema(description = "User's password (min 8 characters with at least one uppercase letter, one lowercase letter, one digit, and one special character)", 
            example = "Password123!")
    private String password;
} 