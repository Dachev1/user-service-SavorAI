package dev.idachev.recipeservice.web.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.Map;

/**
 * Error response DTO for consistent API error handling.
 * Provides standardized error information that follows REST API conventions.
 * Includes error status, message, timestamp, and detailed validation errors.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Standardized error response for API errors")
public class ErrorResponse {
    // HTTP status code
    @Schema(description = "HTTP status code", example = "400")
    private int status;
    
    // Error message
    @Schema(description = "Human-readable error message", example = "Validation failed: Recipe title is required")
    private String message;
    
    // When the error occurred
    @Schema(description = "Timestamp when the error occurred", example = "2023-03-15T10:15:30")
    private LocalDateTime timestamp;
    
    // Field-specific validation errors (key = field name, value = error message)
    @Schema(description = "Field-specific validation errors (key = field name, value = error message)", 
            example = "{\"title\":\"Recipe title is required\",\"ingredients\":\"At least one ingredient is required\"}")
    private Map<String, String> details;
} 