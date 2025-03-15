package dev.idachev.recipeservice.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Exception thrown when a user attempts to access a resource they don't own
 */
@ResponseStatus(HttpStatus.FORBIDDEN)
public class UnauthorizedAccessException extends RuntimeException {

    public UnauthorizedAccessException(String message) {
        super(message);
    }
} 