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
    @Schema(description = "User's unique identifier")
    private UUID id;
    
    @Schema(description = "User's username", example = "johndoe")
    private String username;
    
    @Schema(description = "User's email address", example = "john.doe@example.com")
    private String email;
    
    @Schema(description = "Whether the user's email is verified", example = "true")
    private boolean verified;
    
    @Schema(description = "Whether verification is pending", example = "false")
    private boolean verificationPending;
    
    @Schema(description = "User's role", example = "USER")
    private String role;
    
    @Schema(description = "When the user account was created")
    private LocalDateTime createdOn;
    
    @Schema(description = "Timestamp of the user's last login")
    private LocalDateTime lastLogin;
} 