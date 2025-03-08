package dev.idachev.userservice.web.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * Response DTO for email verification and other verification operations.
 * Contains information about the success/failure of the verification operation
 * and additional details that might be useful to the client.
 */
@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class VerificationResponse {
    
    /**
     * Indicates whether the verification was successful
     */
    private boolean success;
    
    /**
     * A message describing the result of the verification
     */
    private String message;
    
    /**
     * Timestamp of when the verification was processed
     */
    @Builder.Default
    private LocalDateTime timestamp = LocalDateTime.now();
    
    /**
     * Optional field for additional data that might be needed by the client
     */
    private Object data;
    
    /**
     * Optional redirection URL that the client can use after verification
     */
    private String redirectUrl;
    
    /**
     * Creates a success response with a message
     * 
     * @param message Success message
     * @return VerificationResponse with success=true
     */
    public static VerificationResponse success(String message) {
        return VerificationResponse.builder()
                .success(true)
                .message(message)
                .build();
    }
    
    /**
     * Creates a failure response with a message
     * 
     * @param message Error message
     * @return VerificationResponse with success=false
     */
    public static VerificationResponse failure(String message) {
        return VerificationResponse.builder()
                .success(false)
                .message(message)
                .build();
    }
} 