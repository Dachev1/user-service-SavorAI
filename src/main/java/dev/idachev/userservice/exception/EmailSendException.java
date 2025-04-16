package dev.idachev.userservice.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Exception for email delivery failures
 */
@ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
public class EmailSendException extends RuntimeException {
    
    public EmailSendException(String message) {
        super(message);
    }
    
    public EmailSendException(String message, Throwable cause) {
        super(message, cause);
    }
} 