package dev.idachev.userservice.web;

import dev.idachev.userservice.exception.AuthenticationException;
import dev.idachev.userservice.exception.DuplicateUserException;
import dev.idachev.userservice.exception.InvalidRequestException;
import dev.idachev.userservice.exception.ResourceNotFoundException;
import dev.idachev.userservice.exception.UserServiceException;
import dev.idachev.userservice.exception.VerificationException;
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
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.multipart.MaxUploadSizeExceededException;
import org.springframework.web.servlet.resource.NoResourceFoundException;

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
        return createResponse(HttpStatus.UNAUTHORIZED, "Invalid credentials");
    }

    /**
     * Handles authentication and authorization exceptions
     */
    @ExceptionHandler(AuthenticationException.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public ResponseEntity<GenericResponse> handleAuthenticationException(AuthenticationException ex) {
        log.warn("Authentication error: {}", ex.getMessage());
        if (ex.getMessage().contains(ALREADY_LOGGED_IN_MSG)) {
            return createResponse(HttpStatus.BAD_REQUEST, ex.getMessage());
        }
        return createResponse(HttpStatus.UNAUTHORIZED, ex.getMessage());
    }

    /**
     * Handles resource not found exceptions (UsernameNotFoundException is handled separately)
     */
    @ExceptionHandler(ResourceNotFoundException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND) // Ensure 404 is always returned
    public ResponseEntity<GenericResponse> handleResourceNotFoundException(ResourceNotFoundException ex) {
        log.warn("Resource not found: {}", ex.getMessage());
        // Always return 404 for ResourceNotFoundException
        return createResponse(HttpStatus.NOT_FOUND, ex.getMessage());
    }

    /**
     * Specifically handles UsernameNotFoundException (often implies invalid credentials during login)
     */
    @ExceptionHandler(UsernameNotFoundException.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public ResponseEntity<GenericResponse> handleUsernameNotFoundException(UsernameNotFoundException ex) {
        log.warn("Resource not found (Username): {}", ex.getMessage());
        // Treat as invalid credentials during authentication attempt
        return createResponse(HttpStatus.UNAUTHORIZED, "Invalid credentials");
    }

    /**
     * Handles user not found exceptions from our custom exception type
     */
    @ExceptionHandler(dev.idachev.userservice.exception.UserNotFoundException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public ResponseEntity<GenericResponse> handleUserNotFoundException(dev.idachev.userservice.exception.UserNotFoundException ex) {
        log.warn("User not found: {}", ex.getMessage());

        // Always return NOT_FOUND for user not found exceptions
        return createResponse(HttpStatus.NOT_FOUND, ex.getMessage());
    }

    /**
     * Handles invalid token exceptions
     */
    @ExceptionHandler(dev.idachev.userservice.exception.InvalidTokenException.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public ResponseEntity<GenericResponse> handleInvalidTokenException(dev.idachev.userservice.exception.InvalidTokenException ex) {
        log.warn("Invalid token: {}", ex.getMessage());

        // Always return UNAUTHORIZED for token validation failures
        return createResponse(HttpStatus.UNAUTHORIZED, ex.getMessage());
    }

    /**
     * Handles validation errors from request body validation
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ResponseEntity<GenericResponse> handleValidationExceptions(MethodArgumentNotValidException ex) {
        log.debug("Validation error on request: {}", ex.getMessage());

        String errorMessage = ex.getBindingResult().getFieldErrors().stream()
                .map(error -> error.getField() + ": " + error.getDefaultMessage())
                .collect(Collectors.joining("; "));

        return createResponse(HttpStatus.BAD_REQUEST, errorMessage);
    }

    /**
     * Handles validation errors for request parameters
     */
    @ExceptionHandler(jakarta.validation.ConstraintViolationException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ResponseEntity<GenericResponse> handleConstraintViolation(jakarta.validation.ConstraintViolationException ex) {
        log.debug("Constraint violation: {}", ex.getMessage());

        String errorMessage = ex.getConstraintViolations().stream()
                .map(violation -> {
                    String path = violation.getPropertyPath().toString();
                    String param = path.contains(".")
                            ? path.substring(path.lastIndexOf('.') + 1)
                            : path;
                    return param + ": " + violation.getMessage();
                })
                .collect(Collectors.joining("; "));

        return createResponse(HttpStatus.BAD_REQUEST, errorMessage);
    }

    /**
     * Handles errors when a request parameter cannot be converted to the required type (e.g., String to Enum).
     */
    @ExceptionHandler(MethodArgumentTypeMismatchException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ResponseEntity<GenericResponse> handleTypeMismatch(MethodArgumentTypeMismatchException ex) {
        String error = String.format("Invalid value '%s' for parameter '%s'. Required type is '%s'.",
                ex.getValue(), ex.getName(), ex.getRequiredType().getSimpleName());
        log.warn("Type mismatch: {}", error);
        return createResponse(HttpStatus.BAD_REQUEST, error);
    }

    /**
     * Handles business logic errors resulting in bad requests
     */
    @ExceptionHandler({IllegalArgumentException.class})
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ResponseEntity<GenericResponse> handleBadRequestExceptions(Exception ex) {
        log.warn("Bad request: {}", ex.getMessage());
        return createResponse(HttpStatus.BAD_REQUEST, ex.getMessage());
    }

    /**
     * Handles invalid request exceptions
     */
    @ExceptionHandler(InvalidRequestException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ResponseEntity<GenericResponse> handleInvalidRequestException(InvalidRequestException ex) {
        log.warn("Invalid request: {}", ex.getMessage());
        return createResponse(HttpStatus.BAD_REQUEST, ex.getMessage());
    }

    /**
     * Handles duplicate user registration attempts
     */
    @ExceptionHandler(DuplicateUserException.class)
    @ResponseStatus(HttpStatus.CONFLICT) // Changed back to CONFLICT from BAD_REQUEST
    public ResponseEntity<GenericResponse> handleDuplicateUserException(DuplicateUserException ex) {
        log.warn("Duplicate user error: {}", ex.getMessage());
        // Return 409 Conflict as this is the semantically correct status
        return createResponse(HttpStatus.CONFLICT, ex.getMessage());
    }

    /**
     * Handles UserServiceException - base exception for service-specific errors
     */
    @ExceptionHandler(UserServiceException.class)
    public ResponseEntity<GenericResponse> handleUserServiceException(UserServiceException ex) {
        log.warn("User service error: {} with code: {}", ex.getMessage(), ex.getErrorCode());

        // Determine HTTP status based on error code or default to BAD_REQUEST
        HttpStatus status = HttpStatus.BAD_REQUEST;
        if (ex.getErrorCode().startsWith("AUTH_")) {
            status = HttpStatus.UNAUTHORIZED;
        } else if (ex.getErrorCode().startsWith("FORBIDDEN_")) {
            status = HttpStatus.FORBIDDEN;
        } else if (ex.getErrorCode().startsWith("NOT_FOUND_")) {
            status = HttpStatus.NOT_FOUND;
        } else if (ex.getErrorCode().startsWith("CONFLICT_")) {
            status = HttpStatus.CONFLICT;
        }

        GenericResponse errorResponse = GenericResponse.builder()
                .status(status.value())
                .message(ex.getMessage())
                .timestamp(LocalDateTime.now())
                .success(false)
                .errorCode(ex.getErrorCode()) // Include the error code in the response
                .build();

        return ResponseEntity.status(status).body(errorResponse);
    }

    /**
     * Handles authorization exceptions (Access Denied)
     */
    @ExceptionHandler(AccessDeniedException.class)
    @ResponseStatus(HttpStatus.FORBIDDEN)
    public ResponseEntity<GenericResponse> handleAccessDeniedException(AccessDeniedException ex) {
        return createResponse(HttpStatus.FORBIDDEN, ex.getMessage());
    }

    /**
     * Handles file upload size exceptions
     */
    @ExceptionHandler(MaxUploadSizeExceededException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ResponseEntity<GenericResponse> handleMaxSizeException(MaxUploadSizeExceededException ex) {
        return createResponse(HttpStatus.BAD_REQUEST, "File is too large. Maximum allowed size is 5MB.");
    }

    /**
     * Handles account verification exceptions
     */
    @ExceptionHandler(dev.idachev.userservice.exception.AccountVerificationException.class)
    @ResponseStatus(HttpStatus.FORBIDDEN)
    public ResponseEntity<GenericResponse> handleAccountVerificationException(dev.idachev.userservice.exception.AccountVerificationException ex) {
        log.warn("Account verification error: {}", ex.getMessage());
        return createResponse(HttpStatus.FORBIDDEN, ex.getMessage());
    }

    /**
     * Handles verification token exceptions
     */
    @ExceptionHandler(VerificationException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ResponseEntity<GenericResponse> handleVerificationException(VerificationException ex) {
        log.warn("Verification error: {}", ex.getMessage());
        return createResponse(HttpStatus.BAD_REQUEST, ex.getMessage());
    }

    /**
     * Handles exceptions for operations forbidden by business logic (e.g., admin self-ban).
     */
    @ExceptionHandler(dev.idachev.userservice.exception.OperationForbiddenException.class)
    @ResponseStatus(HttpStatus.FORBIDDEN)
    public ResponseEntity<GenericResponse> handleOperationForbiddenException(dev.idachev.userservice.exception.OperationForbiddenException ex) {
        log.warn("Forbidden operation attempt: {}", ex.getMessage());
        return createResponse(HttpStatus.FORBIDDEN, ex.getMessage());
    }

    /**
     * Handles failures during email sending.
     */
    @ExceptionHandler(dev.idachev.userservice.exception.EmailSendException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR) // Or SERVICE_UNAVAILABLE? 500 is common.
    public ResponseEntity<GenericResponse> handleEmailSendException(dev.idachev.userservice.exception.EmailSendException ex) {
        // Log as error as it indicates a backend system failure
        log.error("Email sending failed: {}", ex.getMessage(), ex.getCause()); 
        return createResponse(HttpStatus.INTERNAL_SERVER_ERROR, 
                              "Failed to send email. Please try again later or contact support.");
    }

    /**
     * Handles duplicate user registration attempts (e.g., username/email taken)
     */
    @ExceptionHandler(dev.idachev.userservice.exception.UserAlreadyExistsException.class)
    @ResponseStatus(HttpStatus.CONFLICT)
    public ResponseEntity<GenericResponse> handleUserAlreadyExistsException(dev.idachev.userservice.exception.UserAlreadyExistsException ex) {
        log.warn("User already exists error: {}", ex.getMessage());
        return createResponse(HttpStatus.CONFLICT, ex.getMessage());
    }

    /**
     * Fallback handler for all other uncaught exceptions
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<GenericResponse> handleGenericException(Exception ex) {
        // Specific handling for NoResourceFoundException (e.g., static assets)
        if (ex instanceof NoResourceFoundException) { // Use instanceof
             log.warn("Static resource not found: {}", ex.getMessage());
             // Return 404 using the helper method
             return createResponse(HttpStatus.NOT_FOUND, "Resource not found");
        }
        
        // Log all other unexpected exceptions as errors
        log.error("Unhandled internal server error", ex);

        // Return generic 500 response
        return createResponse(HttpStatus.INTERNAL_SERVER_ERROR, 
                              "An unexpected internal error occurred. Please try again later.");
    }

    /**
     * Helper method to create consistent error responses
     */
    private ResponseEntity<GenericResponse> createResponse(HttpStatus status, String message) {
        GenericResponse errorResponse = GenericResponse.builder()
                .status(status.value())
                .message(message)
                .timestamp(LocalDateTime.now())
                .success(false)
                .build();

        return ResponseEntity.status(status).body(errorResponse);
    }
} 
