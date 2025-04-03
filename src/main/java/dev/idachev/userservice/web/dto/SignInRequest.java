package dev.idachev.userservice.web.dto;

import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonIgnore;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.*;

/**
 * Data Transfer Object for sign-in requests
 */
@Data
@Builder
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Sign-in request parameters")
public class SignInRequest {

    @NotBlank(message = "Username or email cannot be empty")
    @Size(max = 100, message = "Username or email must not exceed 100 characters")
    @Schema(description = "User's email address or username", example = "john.doe@example.com or johndoe")
    @JsonAlias("email") // Support legacy frontend requests still using "email" field
    private String identifier;

    @NotBlank(message = "Password cannot be empty")
    @Schema(description = "User's password", example = "password123")
    private String password;
} 