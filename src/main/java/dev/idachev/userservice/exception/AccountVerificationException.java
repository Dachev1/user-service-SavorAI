package dev.idachev.userservice.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Exception thrown when a user attempts to log in before their account is verified.
 */
@ResponseStatus(HttpStatus.FORBIDDEN)
public class AccountVerificationException extends RuntimeException {
    
    public AccountVerificationException(String message) {
        super(message);
    }
    
    public AccountVerificationException(String message, Throwable cause) {
        super(message, cause);
    }
} 