package dev.idachev.userservice.web.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Data Transfer Object for token verification requests
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Token verification request parameters")
public class TokenRequest {
    
    @NotBlank(message = "Token cannot be empty")
    @Schema(description = "Verification token", example = "a1b2c3d4-e5f6-g7h8-i9j0-k1l2m3n4o5p6")
    private String token;
} 