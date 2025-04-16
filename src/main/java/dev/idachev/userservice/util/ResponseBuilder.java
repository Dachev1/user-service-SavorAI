package dev.idachev.userservice.util;

import dev.idachev.userservice.web.dto.GenericResponse;
import org.springframework.http.HttpStatus;

import java.time.LocalDateTime;

/**
 * Utility for building standardized API responses
 */
public final class ResponseBuilder {
    
    private ResponseBuilder() {
        // Private constructor to prevent instantiation
    }
    
    /**
     * Creates a success response with HTTP 200
     */
    public static GenericResponse success(String message) {
        return buildResponse(HttpStatus.OK, message, true);
    }
    
    /**
     * Creates a success response with custom status
     */
    public static GenericResponse success(HttpStatus status, String message) {
        return buildResponse(status, message, true);
    }
    
    /**
     * Creates an error response with HTTP 400
     */
    public static GenericResponse error(String message) {
        return buildResponse(HttpStatus.BAD_REQUEST, message, false);
    }
    
    /**
     * Creates an error response with custom status
     */
    public static GenericResponse error(HttpStatus status, String message) {
        return buildResponse(status, message, false);
    }
    
    /**
     * Common builder for all responses
     */
    private static GenericResponse buildResponse(HttpStatus status, String message, boolean success) {
        return GenericResponse.builder()
                .status(status.value())
                .message(message)
                .timestamp(LocalDateTime.now())
                .success(success)
                .build();
    }
} 