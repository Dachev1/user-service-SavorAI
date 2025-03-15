package dev.idachev.userservice.web.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * Standard error response DTO for all API errors
 */
@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Standard error response for all API errors")
public class ErrorResponse {
    @Schema(description = "HTTP status code", example = "400")
    private Integer status;
    
    @Schema(description = "Error message", example = "Validation failed: email is required")
    private String message;
    
    @Schema(description = "Timestamp when the error occurred")
    private LocalDateTime timestamp;
} 