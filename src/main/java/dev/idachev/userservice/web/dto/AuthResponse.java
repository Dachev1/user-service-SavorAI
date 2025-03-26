package dev.idachev.userservice.web.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Getter
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Schema(description = "Authentication response with JWT token and user information")
public class AuthResponse {
    @Schema(description = "JWT token for authorization", example = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")
    private String token;
    
    @Schema(description = "User's username", example = "johndoe")
    private String username;
    
    @Schema(description = "User's email address", example = "john.doe@example.com")
    private String email;
    
    @Schema(description = "User's role", example = "USER")
    private String role;
    
    @Schema(description = "Whether the user's email is verified", example = "true")
    private boolean verified;
    
    @Schema(description = "Whether verification is pending", example = "false")
    private boolean verificationPending;
    
    @Schema(description = "Timestamp of the user's last login")
    private LocalDateTime lastLogin;
    
    @Schema(description = "Whether the operation was successful", example = "true")
    private boolean success;
    
    @Schema(description = "Response message, can contain success or error details")
    private String message;
    
    @Schema(description = "User object that matches frontend expectations")
    private UserResponse user;
} 