package dev.idachev.userservice.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Exception thrown when attempting to create a user with a username or email that already exists.
 */
@ResponseStatus(HttpStatus.CONFLICT)
public class DuplicateUserException extends RuntimeException {
    
    public DuplicateUserException(String message) {
        super(message);
    }
    
    public DuplicateUserException(String message, Throwable cause) {
        super(message, cause);
    }
} 