package dev.idachev.userservice.exception;

/**
 * Exception for resource conflicts like duplicate usernames or emails
 */
public class ResourceConflictException extends RuntimeException {

    public ResourceConflictException(String message) {
        super(message);
    }

    public ResourceConflictException(String message, Throwable cause) {
        super(message, cause);
    }
} 