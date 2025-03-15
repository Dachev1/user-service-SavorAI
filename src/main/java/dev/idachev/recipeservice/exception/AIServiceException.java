package dev.idachev.recipeservice.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Exception thrown when there is an error with the AI service.
 */
@ResponseStatus(HttpStatus.SERVICE_UNAVAILABLE)
public class AIServiceException extends RuntimeException {

    public AIServiceException(String message) {
        super(message);
    }

    public AIServiceException(String message, Throwable cause) {
        super(message, cause);
    }
} 