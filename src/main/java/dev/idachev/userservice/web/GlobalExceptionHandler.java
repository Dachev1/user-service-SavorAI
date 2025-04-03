package dev.idachev.userservice.web;

import dev.idachev.userservice.exception.AuthenticationException;
import dev.idachev.userservice.exception.DuplicateUserException;
import dev.idachev.userservice.exception.ResourceNotFoundException;
import dev.idachev.userservice.web.dto.GenericResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.multipart.MaxUploadSizeExceededException;

import java.time.LocalDateTime;
import java.util.stream.Collectors;

/**
 * Global exception handler for centralized error handling
 */
@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final String ALREADY_LOGGED_IN_MSG = "You are already logged in";

    /**
     * Handles authentication and authorization exceptions
     */
    @ExceptionHandler(BadCredentialsException.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public ResponseEntity<GenericResponse> handleBadCredentialsException(BadCredentialsException ex) {
        // For security reasons, use a generic error message regardless of the actual exception message
        log.error("Authentication error (bad credentials): {}", ex.getMessage());
        return createResponse(HttpStatus.UNAUTHORIZED, "Authentication failed. Invalid username or password.");
    }

    /**
     * Handles authentication and authorization exceptions
     */
    @ExceptionHandler(AuthenticationException.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public ResponseEntity<GenericResponse> handleAuthenticationException(AuthenticationException ex) {
        // Special case for already logged in users - use 400 (Bad Request) instead of 401 (Unauthorized)
        if (ex.getMessage().contains(ALREADY_LOGGED_IN_MSG)) {
            log.warn("Login attempt while already logged in: {}", ex.getMessage());
            return createResponse(HttpStatus.BAD_REQUEST, ex.getMessage());
        }

        // Standard authentication errors
        log.error("Authentication error: {}", ex.getMessage());
        return createResponse(HttpStatus.UNAUTHORIZED, ex.getMessage());
    }

    /**
     * Handles resource not found exceptions
     */
    @ExceptionHandler({UsernameNotFoundException.class, ResourceNotFoundException.class})
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public ResponseEntity<GenericResponse> handleNotFoundExceptions(Exception ex) {
        log.error("Resource not found: {}", ex.getMessage());
        return createResponse(HttpStatus.NOT_FOUND, ex.getMessage());
    }

    /**
     * Handles validation errors from request body validation
     * Returns a standardized error response with consolidated validation errors
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ResponseEntity<GenericResponse> handleValidationExceptions(MethodArgumentNotValidException ex) {
        // Extract and format field validation errors
        String errorMessage = ex.getBindingResult().getFieldErrors().stream()
                .map(error -> error.getField() + ": " + error.getDefaultMessage())
                .collect(Collectors.joining("; "));

        log.error("Validation error: {}", errorMessage);

        // Return standardized error response
        return createResponse(HttpStatus.BAD_REQUEST, "Validation failed: " + errorMessage);
    }

    /**
     * Handles validation errors for request parameters
     */
    @ExceptionHandler(jakarta.validation.ConstraintViolationException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ResponseEntity<GenericResponse> handleConstraintViolation(jakarta.validation.ConstraintViolationException ex) {
        String errorMessage = ex.getConstraintViolations().stream()
                .map(violation -> {
                    String path = violation.getPropertyPath().toString();
                    String param = path.contains(".")
                            ? path.substring(path.lastIndexOf('.') + 1)
                            : path;
                    return param + ": " + violation.getMessage();
                })
                .collect(Collectors.joining("; "));

        log.error("Constraint violation: {}", errorMessage);

        return createResponse(HttpStatus.BAD_REQUEST, "Validation failed: " + errorMessage);
    }

    /**
     * Handles business logic errors resulting in bad requests
     */
    @ExceptionHandler({IllegalArgumentException.class})
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ResponseEntity<GenericResponse> handleBadRequestExceptions(Exception ex) {
        log.error("Bad request: {}", ex.getMessage());
        return createResponse(HttpStatus.BAD_REQUEST, ex.getMessage());
    }

    /**
     * Handles duplicate user registration attempts
     */
    @ExceptionHandler(DuplicateUserException.class)
    @ResponseStatus(HttpStatus.CONFLICT)
    public ResponseEntity<GenericResponse> handleDuplicateUserException(DuplicateUserException ex) {
        log.error("User conflict: {}", ex.getMessage());

        // Provide a structured response with the specific field causing the conflict
        GenericResponse response = GenericResponse.builder()
                .status(HttpStatus.CONFLICT.value())
                .message(ex.getMessage())
                .timestamp(LocalDateTime.now())
                .success(false)
                .build();

        return ResponseEntity.status(HttpStatus.CONFLICT).body(response);
    }

    /**
     * Handles authorization exceptions (Access Denied)
     */
    @ExceptionHandler(AccessDeniedException.class)
    @ResponseStatus(HttpStatus.FORBIDDEN)
    public ResponseEntity<GenericResponse> handleAccessDeniedException(AccessDeniedException ex) {
        log.error("Authorization error: {}", ex.getMessage());
        return createResponse(HttpStatus.FORBIDDEN, ex.getMessage());
    }

    /**
     * Handles file upload size exceptions
     */
    @ExceptionHandler(MaxUploadSizeExceededException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ResponseEntity<GenericResponse> handleMaxSizeException(MaxUploadSizeExceededException ex) {
        log.warn("File size exceeded: {}", ex.getMessage());
        return createResponse(HttpStatus.BAD_REQUEST, "File is too large. Maximum allowed size is 5MB.");
    }

    /**
     * Fallback handler for all other uncaught exceptions
     */
    @ExceptionHandler(Exception.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public ResponseEntity<GenericResponse> handleGenericException(Exception ex) {
        // Log the full stack trace for unexpected errors
        log.error("Unexpected error: {}", ex.getMessage(), ex);

        // Don't expose internal error details to the client
        return createResponse(HttpStatus.INTERNAL_SERVER_ERROR,
                "An unexpected error occurred. Please try again later or contact support.");
    }

    /**
     * Creates a standardized error response
     */
    private ResponseEntity<GenericResponse> createResponse(HttpStatus status, String message) {
        GenericResponse errorResponse = GenericResponse.builder()
                .status(status.value())
                .message(message)
                .timestamp(LocalDateTime.now())
                .build();

        return ResponseEntity.status(status).body(errorResponse);
    }
} 