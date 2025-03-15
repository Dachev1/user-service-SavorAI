package dev.idachev.recipeservice.exception;

import dev.idachev.recipeservice.web.dto.ErrorResponse;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.validation.FieldError;
import org.springframework.validation.ObjectError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

/**
 * Global exception handler for the application.
 * Handles various exceptions and converts them to standardized error responses.
 * Follows Single Responsibility Principle by focusing solely on exception handling.
 */
@ControllerAdvice
@Slf4j
public class GlobalExceptionHandler {

    /**
     * Handles ResourceNotFoundException and returns a NOT_FOUND response.
     *
     * @param ex The exception that was thrown
     * @return ResponseEntity with error details
     */
    @ExceptionHandler(ResourceNotFoundException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    @ApiResponse(responseCode = "404", description = "Resource not found",
            content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    public ResponseEntity<ErrorResponse> handleResourceNotFoundException(ResourceNotFoundException ex) {
        log.error("Resource not found: {}", ex.getMessage());
        
        ErrorResponse errorResponse = new ErrorResponse(
                HttpStatus.NOT_FOUND.value(),
                ex.getMessage(),
                LocalDateTime.now(),
                null
        );
        
        return new ResponseEntity<>(errorResponse, HttpStatus.NOT_FOUND);
    }

    /**
     * Handles validation exceptions and returns a BAD_REQUEST response with field-specific errors.
     *
     * @param ex The validation exception
     * @return ResponseEntity with validation error details
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ApiResponse(responseCode = "400", description = "Validation error",
            content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    public ResponseEntity<ErrorResponse> handleValidationExceptions(MethodArgumentNotValidException ex) {
        log.error("Validation error: {}", ex.getMessage());
        
        Map<String, String> errors = new HashMap<>();
        for (ObjectError error : ex.getBindingResult().getAllErrors()) {
            String fieldName = error instanceof FieldError ? ((FieldError) error).getField() : error.getObjectName();
            String errorMessage = error.getDefaultMessage();
            errors.put(fieldName, errorMessage);
        }
        
        ErrorResponse errorResponse = new ErrorResponse(
                HttpStatus.BAD_REQUEST.value(),
                "Validation failed",
                LocalDateTime.now(),
                errors
        );
        
        return new ResponseEntity<>(errorResponse, HttpStatus.BAD_REQUEST);
    }

    /**
     * Handles BadRequestException and returns a BAD_REQUEST response.
     *
     * @param ex The exception that was thrown
     * @return ResponseEntity with error details
     */
    @ExceptionHandler(BadRequestException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ApiResponse(responseCode = "400", description = "Bad request",
            content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    public ResponseEntity<ErrorResponse> handleBadRequestException(BadRequestException ex) {
        log.error("Bad request: {}", ex.getMessage());
        
        ErrorResponse errorResponse = new ErrorResponse(
                HttpStatus.BAD_REQUEST.value(),
                ex.getMessage(),
                LocalDateTime.now(),
                null
        );
        
        return new ResponseEntity<>(errorResponse, HttpStatus.BAD_REQUEST);
    }

    /**
     * Handles common bad request type exceptions
     *
     * @param ex The exception that was thrown
     * @return ResponseEntity with error details
     */
    @ExceptionHandler({
            HttpMessageNotReadableException.class,
            MethodArgumentTypeMismatchException.class,
            MissingServletRequestParameterException.class,
            IllegalArgumentException.class
    })
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ApiResponse(responseCode = "400", description = "Invalid request format or parameters",
            content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    public ResponseEntity<ErrorResponse> handleCommonBadRequestExceptions(Exception ex) {
        String message = getDetailedErrorMessage(ex);
        log.error("Bad request: {}", message);
        
        ErrorResponse errorResponse = new ErrorResponse(
                HttpStatus.BAD_REQUEST.value(),
                message,
                LocalDateTime.now(),
                null
        );
        
        return new ResponseEntity<>(errorResponse, HttpStatus.BAD_REQUEST);
    }

    /**
     * Handles unauthorized access exceptions (authentication failures)
     */
    @ExceptionHandler({UnauthorizedException.class})
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    @ApiResponse(responseCode = "401", description = "Authentication failed",
            content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    public ResponseEntity<ErrorResponse> handleUnauthorizedException(UnauthorizedException ex) {
        log.warn("Authentication failed: {}", ex.getMessage());
        
        ErrorResponse errorResponse = new ErrorResponse(
                HttpStatus.UNAUTHORIZED.value(),
                "Your session has expired or is invalid. Please log in again.",
                LocalDateTime.now(),
                null
        );
        
        return new ResponseEntity<>(errorResponse, HttpStatus.UNAUTHORIZED);
    }

    /**
     * Handles all other exceptions and returns an INTERNAL_SERVER_ERROR response.
     *
     * @param ex The exception that was thrown
     * @return ResponseEntity with error details
     */
    @ExceptionHandler(Exception.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    @ApiResponse(responseCode = "500", description = "Internal server error",
            content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    public ResponseEntity<ErrorResponse> handleGenericException(Exception ex) {
        log.error("Unexpected error occurred", ex);
        
        ErrorResponse errorResponse = new ErrorResponse(
                HttpStatus.INTERNAL_SERVER_ERROR.value(),
                "An unexpected error occurred",
                LocalDateTime.now(),
                null
        );
        
        return new ResponseEntity<>(errorResponse, HttpStatus.INTERNAL_SERVER_ERROR);
    }
    
    /**
     * Get detailed error message based on exception type
     */
    private String getDetailedErrorMessage(Exception ex) {
        if (ex instanceof HttpMessageNotReadableException) {
            return "Invalid request format: The request body could not be read";
        } else if (ex instanceof MethodArgumentTypeMismatchException mae) {
            return "Invalid parameter type: " + mae.getName();
        } else if (ex instanceof MissingServletRequestParameterException msrpe) {
            return "Missing required parameter: " + msrpe.getParameterName();
        }
        return ex.getMessage();
    }
} 