package dev.idachev.userservice.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Exception thrown when a user attempts an operation they are not allowed to perform,
 * often related to modifying resources they don't own or have permission for (e.g., admin self-operations).
 */
@ResponseStatus(HttpStatus.FORBIDDEN) // Maps to HTTP 403 Forbidden
public class OperationForbiddenException extends RuntimeException {

    public OperationForbiddenException(String message) {
        super(message);
    }

    public OperationForbiddenException(String message, Throwable cause) {
        super(message, cause);
    }
} 