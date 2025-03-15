package dev.idachev.userservice.exception;

import lombok.Getter;

@Getter
public class UserServiceException extends RuntimeException {
    private final String errorCode;
    
    public UserServiceException(String message, String errorCode) {
        super(message);
        this.errorCode = errorCode;
    }
} 