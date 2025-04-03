package dev.idachev.userservice.web.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Data;

import java.time.LocalDateTime;

/**
 * Standard response DTO for API operations
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Standard response for API operations")
public class GenericResponse {
    @NotNull(message = "Status cannot be null")
    @Schema(description = "Response status code", example = "200")
    private Integer status;
    
    @Schema(description = "Response message", example = "Operation completed successfully")
    private String message;
    
    @NotNull(message = "Timestamp cannot be null")
    @Schema(description = "Response timestamp", example = "2024-03-20T15:30:00")
    private LocalDateTime timestamp;

    private boolean success;
} 