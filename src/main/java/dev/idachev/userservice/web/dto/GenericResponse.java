package dev.idachev.userservice.web.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * Standard response DTO for API operations
 */
@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Standard response for API operations")
public class GenericResponse {
    @Schema(description = "Response HTTP status code", example = "200")
    private Integer status;
    
    @Schema(description = "Response message", example = "Operation completed successfully")
    private String message;
    
    @Builder.Default
    @Schema(description = "Response timestamp", example = "2024-03-20T15:30:00")
    private LocalDateTime timestamp = LocalDateTime.now();

    @Schema(description = "Indicates if the operation was successful", example = "true")
    private boolean success;
    
    @Schema(description = "Optional error code for failed operations", example = "AUTH_INVALID", nullable = true)
    private String errorCode;

    public static GenericResponse success(String message) {
        return GenericResponse.builder()
                .status(200)
                .message(message)
                .success(true)
                .timestamp(LocalDateTime.now())
                .build();
    }

    public static GenericResponse error(int status, String message, String errorCode) {
        return GenericResponse.builder()
                .status(status)
                .message(message)
                .success(false)
                .errorCode(errorCode)
                .timestamp(LocalDateTime.now())
                .build();
    }
} 