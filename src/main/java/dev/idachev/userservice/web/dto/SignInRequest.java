package dev.idachev.userservice.web.dto;

import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonIgnore;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
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
    @Size(min = 6, message = "Password must be at least 6 characters")
    @Schema(description = "User's password", example = "Password123!")
    private String password;
} 