package dev.idachev.userservice.web.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "User information response")
public class UserResponse {

    @NotNull(message = "ID cannot be null")
    @Schema(description = "User ID", example = "123")
    private UUID id;

    @NotBlank(message = "Username cannot be empty")
    @Size(min = 3, max = 30, message = "Username must be between 3 and 30 characters")
    @Pattern(regexp = "^[a-zA-Z0-9_-]+$", message = "Username can only contain letters, numbers, underscores, and hyphens")
    @Schema(description = "Username", example = "johnsmith")
    private String username;

    @Email(message = "Email must be valid")
    @NotBlank(message = "Email cannot be empty")
    @Schema(description = "Email address", example = "john@example.com")
    private String email;

    @Schema(description = "Whether the user's email is verified", example = "true")
    private boolean verified;

    @Schema(description = "Whether email verification is pending", example = "false")
    private boolean verificationPending;

    @Schema(description = "Whether the user is banned", example = "false")
    private boolean banned;

    @NotBlank(message = "Role cannot be empty")
    @Schema(description = "User role", example = "USER")
    private String role;

    @NotNull(message = "Creation date cannot be null")
    @Schema(description = "Account creation timestamp", example = "2024-03-20T15:30:00")
    private LocalDateTime createdOn;

    @Schema(description = "Last login timestamp", example = "2024-03-20T15:30:00")
    private LocalDateTime lastLogin;
} 