package dev.idachev.userservice.web.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Password change request")
public class PasswordChangeRequest {
    
    @NotBlank(message = "Current password is required")
    @Schema(description = "User's current password", example = "oldPassword123")
    private String currentPassword;
    
    @NotBlank(message = "New password is required")
    @Schema(description = "New password to set", example = "newPassword123")
    private String newPassword;
    
    @NotBlank(message = "Password confirmation is required")
    @Schema(description = "Confirmation of the new password", example = "newPassword123")
    private String confirmPassword;
} 