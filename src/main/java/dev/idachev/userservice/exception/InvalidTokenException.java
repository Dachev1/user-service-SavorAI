package dev.idachev.userservice.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Exception for invalid or expired tokens
 */
@ResponseStatus(HttpStatus.UNAUTHORIZED)
public class InvalidTokenException extends RuntimeException {
    
    public InvalidTokenException(String message) {
        super(message);
    }
    
    public InvalidTokenException(String message, Throwable cause) {
        super(message, cause);
    }
} 