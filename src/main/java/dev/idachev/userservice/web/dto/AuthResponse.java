package dev.idachev.userservice.web.dto;

import java.time.LocalDateTime;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Schema(description = "Authentication response with JWT token and user information")
public class AuthResponse {
    @Schema(description = "JWT token for authentication", example = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")
    private String token;

    @NotBlank(message = "Username cannot be empty")
    @Schema(description = "Username of the authenticated user", example = "johnsmith")
    private String username;

    @Email(message = "Email must be valid")
    @NotBlank(message = "Email cannot be empty")
    @Schema(description = "Email of the authenticated user", example = "john@example.com")
    private String email;

    @NotBlank(message = "Role cannot be empty")
    @Schema(description = "User role", example = "USER")
    private String role;

    @Schema(description = "Whether the user account is enabled (email verified)", example = "true")
    private boolean enabled;

    @Schema(description = "Whether email verification is pending", example = "false")
    private boolean verificationPending;

    @Schema(description = "Whether the user account is banned", example = "false")
    private boolean banned;

    @Schema(description = "Timestamp of last login", example = "2024-03-20T15:30:00")
    private LocalDateTime lastLogin;

    @Schema(description = "Whether the authentication was successful", example = "true")
    private boolean success;

    @Schema(description = "Response message", example = "Authentication successful")
    private String message;

    @Valid
    @Schema(description = "User profile data")
    private UserResponse user;

    /**
     * Constructor for token refresh response
     * 
     * @param token JWT token
     * @param user  User response object
     */
    public AuthResponse(String token, UserResponse user) {
        // Ensure token is never null
        this.token = token != null ? token : "";
        this.user = user;
        
        if (user != null) {
            this.username = user.getUsername();
            this.email = user.getEmail();
            this.role = user.getRole();
            this.enabled = user.isEnabled();
            this.verificationPending = user.isVerificationPending();
            this.banned = user.isBanned();
            this.lastLogin = user.getLastLogin();
        } else {
            // Set default values when user is null to avoid NPEs
            this.username = "";
            this.email = "";
            this.role = "";
            this.enabled = false;
            this.verificationPending = false;
            this.banned = false;
        }
        
        this.success = true;
        this.message = "Token refreshed successfully";
    }
}