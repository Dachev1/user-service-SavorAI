package dev.idachev.recipeservice.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Exception thrown when there is an error communicating with a Feign client.
 */
@ResponseStatus(HttpStatus.SERVICE_UNAVAILABLE)
public class FeignClientException extends RuntimeException {

    public FeignClientException(String message) {
        super(message);
    }

    public FeignClientException(String message, Throwable cause) {
        super(message, cause);
    }
} 