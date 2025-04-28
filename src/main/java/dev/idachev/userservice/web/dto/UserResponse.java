package dev.idachev.userservice.web.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.UUID;

@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "User information response")
public class UserResponse {

    @Schema(description = "User ID", example = "123e4567-e89b-12d3-a456-426614174000")
    private UUID id;

    @Schema(description = "Username", example = "johnsmith")
    private String username;

    @Schema(description = "Email address", example = "john@example.com")
    private String email;

    @Schema(description = "Whether the user's email is verified", example = "true")
    private boolean enabled;

    @Schema(description = "Whether email verification is pending", example = "false")
    private boolean verificationPending;

    @Schema(description = "Whether the user is banned", example = "false")
    private boolean banned;

    @Schema(description = "User role", example = "USER")
    private String role;

    @Schema(description = "Account creation timestamp", example = "2024-03-20T15:30:00")
    private LocalDateTime createdOn;

    @Schema(description = "Last login timestamp", example = "2024-03-20T15:30:00", nullable = true)
    private LocalDateTime lastLogin;
} 