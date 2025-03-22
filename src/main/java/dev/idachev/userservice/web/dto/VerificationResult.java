package dev.idachev.userservice.web.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * DTO to encapsulate the result of email verification
 * Used internally for redirect responses
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class VerificationResult {

    /**
     * Whether the verification was successful
     */
    private boolean success;

    /**
     * Error type (used for redirect query parameter)
     * Will be the simple name of the exception class in case of error
     */
    private String errorType;

    /**
     * Creates a successful verification result
     */
    public static VerificationResult success() {
        return new VerificationResult(true, null);
    }

    /**
     * Creates a failed verification result with error type
     */
    public static VerificationResult failure(String errorType) {
        return new VerificationResult(false, errorType);
    }
} 