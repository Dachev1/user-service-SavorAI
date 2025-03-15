package dev.idachev.recipeservice.exception;

/**
 * Exception thrown when there is an error processing images.
 */
public class ImageProcessingException extends RuntimeException {

    public ImageProcessingException(String message) {
        super(message);
    }

    public ImageProcessingException(String message, Throwable cause) {
        super(message, cause);
    }
} 