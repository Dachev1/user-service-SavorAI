package dev.idachev.userservice.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Exception for verification failures such as invalid verification tokens
 */
@ResponseStatus(HttpStatus.BAD_REQUEST)
public class VerificationException extends RuntimeException {
    
    public VerificationException(String message) {
        super(message);
    }
    
    public VerificationException(String message, Throwable cause) {
        super(message, cause);
    }
} 