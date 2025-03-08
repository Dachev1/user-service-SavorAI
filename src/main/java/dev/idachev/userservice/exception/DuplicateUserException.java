package dev.idachev.userservice.exception;

public class DuplicateUserException extends UserServiceException {
    public DuplicateUserException(String message) {
        super(message, "USER_DUPLICATE");
    }
} 