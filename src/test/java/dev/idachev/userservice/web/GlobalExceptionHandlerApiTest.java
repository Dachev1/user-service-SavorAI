package dev.idachev.userservice.web;

import dev.idachev.userservice.exception.AuthenticationException;
import dev.idachev.userservice.exception.DuplicateUserException;
import dev.idachev.userservice.exception.ResourceNotFoundException;
import dev.idachev.userservice.web.dto.GenericResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;

import static org.assertj.core.api.Assertions.assertThat;

class GlobalExceptionHandlerApiTest {

    private GlobalExceptionHandler exceptionHandler;

    @BeforeEach
    void setup() {
        exceptionHandler = new GlobalExceptionHandler();
    }

    @Test
    void handleNotFoundExceptions_ReturnsNotFoundStatus() {
        // Given
        ResourceNotFoundException exception = new ResourceNotFoundException("Resource not found");

        // When
        ResponseEntity<GenericResponse> response = exceptionHandler.handleNotFoundExceptions(exception);

        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().getStatus()).isEqualTo(404);
        assertThat(response.getBody().getMessage()).isEqualTo("Resource not found");
        assertThat(response.getBody().getTimestamp()).isNotNull();
    }

    @Test
    void handleAuthErrors_ReturnsUnauthorizedStatus() {
        // Given
        BadCredentialsException exception = new BadCredentialsException("Invalid credentials");

        // When
        ResponseEntity<GenericResponse> response = exceptionHandler.handleAuthErrors(exception);

        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().getStatus()).isEqualTo(401);
        assertThat(response.getBody().getMessage()).isEqualTo("Invalid credentials");
        assertThat(response.getBody().getTimestamp()).isNotNull();
    }

    @Test
    void handleAlreadyLoggedIn_ReturnsBadRequestStatus() {
        // Given
        AuthenticationException exception = new AuthenticationException("You are already logged in");

        // When
        ResponseEntity<GenericResponse> response = exceptionHandler.handleAuthErrors(exception);

        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().getStatus()).isEqualTo(400);
        assertThat(response.getBody().getMessage()).contains("already logged in");
        assertThat(response.getBody().getTimestamp()).isNotNull();
    }

    @Test
    void handleDuplicateUserException_ReturnsConflictStatus() {
        // Given
        DuplicateUserException exception = new DuplicateUserException("User already exists");

        // When
        ResponseEntity<GenericResponse> response = exceptionHandler.handleDuplicateUserException(exception);

        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().getStatus()).isEqualTo(409);
        assertThat(response.getBody().getMessage()).isEqualTo("User already exists");
        assertThat(response.getBody().getTimestamp()).isNotNull();
    }

    @Test
    void handleBadRequestExceptions_ReturnsBadRequestStatus() {
        // Given
        IllegalArgumentException exception = new IllegalArgumentException("Invalid request parameters");

        // When
        ResponseEntity<GenericResponse> response = exceptionHandler.handleBadRequestExceptions(exception);

        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().getStatus()).isEqualTo(400);
        assertThat(response.getBody().getMessage()).isEqualTo("Invalid request parameters");
        assertThat(response.getBody().getTimestamp()).isNotNull();
    }

    @Test
    void handleGenericException_ReturnsInternalServerErrorStatus() {
        // Given
        RuntimeException exception = new RuntimeException("Unexpected server error");

        // When
        ResponseEntity<GenericResponse> response = exceptionHandler.handleGenericException(exception);

        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().getStatus()).isEqualTo(500);
        assertThat(response.getBody().getMessage()).isNotNull();
        assertThat(response.getBody().getTimestamp()).isNotNull();
    }
} 