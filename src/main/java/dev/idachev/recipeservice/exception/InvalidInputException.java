package dev.idachev.recipeservice.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Exception thrown when input validation fails.
 */
@ResponseStatus(HttpStatus.BAD_REQUEST)
public class InvalidInputException extends RuntimeException {
} 