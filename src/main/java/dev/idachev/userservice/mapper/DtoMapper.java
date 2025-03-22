package dev.idachev.userservice.mapper;

import dev.idachev.userservice.model.User;
import dev.idachev.userservice.web.dto.*;
import lombok.experimental.UtilityClass;

import java.time.LocalDateTime;

/**
 * Utility class for mapping domain entities to DTOs
 */
@UtilityClass
public final class DtoMapper {

    /**
     * Maps a User entity to UserResponse DTO
     *
     * @param user the user entity to map
     * @return the UserResponse DTO
     * @throws IllegalArgumentException if user is null
     */
    public static UserResponse mapToUserResponse(User user) {
        if (user == null) {
            throw new IllegalArgumentException("Cannot map null user to UserResponse");
        }

        return UserResponse.builder()
                .username(user.getUsername())
                .email(user.getEmail())
                .verified(user.isEnabled())
                .verificationPending(user.isVerificationPending())
                .lastLogin(user.getLastLogin())
                .build();
    }

    /**
     * Maps a User entity to AuthResponse DTO with token
     *
     * @param user  the user entity to map
     * @param token the JWT token (can be empty string for unverified users)
     * @return the AuthResponse DTO
     * @throws IllegalArgumentException if user is null
     */
    public static AuthResponse mapToAuthResponse(User user, String token) {
        if (user == null) {
            throw new IllegalArgumentException("Cannot map null user to AuthResponse");
        }

        return AuthResponse.builder()
                .token(token != null ? token : "")
                .username(user.getUsername())
                .email(user.getEmail())
                .verified(user.isEnabled())
                .verificationPending(user.isVerificationPending())
                .lastLogin(user.getLastLogin())
                .success(true)
                .message("")
                .build();
    }

    /**
     * Creates an AuthResponse with success status, message, and basic user info
     * Useful for registration success/failure responses
     *
     * @param user    The user (for username and email)
     * @param success Whether the operation was successful
     * @param message Response message
     * @return AuthResponse with status information and basic user details
     */
    public static AuthResponse mapToAuthResponse(User user, boolean success, String message) {
        if (user == null) {
            return mapToAuthResponse(success, message);
        }

        return AuthResponse.builder()
                .username(user.getUsername())
                .email(user.getEmail())
                .verified(user.isEnabled())
                .verificationPending(user.isVerificationPending())
                .lastLogin(user.getLastLogin())
                .success(success)
                .message(message != null ? message : "")
                .build();
    }

    /**
     * Creates a simple AuthResponse with just success status and message (no user data)
     *
     * @param success Whether the operation was successful
     * @param message Response message
     * @return AuthResponse with status information
     */
    public static AuthResponse mapToAuthResponse(boolean success, String message) {
        return AuthResponse.builder()
                .success(success)
                .message(message != null ? message : "")
                .build();
    }

    /**
     * Maps a User entity to a VerificationResponse DTO
     *
     * @param user    the user entity (can be null for failed verifications)
     * @param success whether verification was successful
     * @param message the message to include in the response
     * @return the VerificationResponse DTO
     */
    public static VerificationResponse mapToVerificationResponse(User user, boolean success, String message) {
        return VerificationResponse.builder()
                .success(success)
                .message(message != null ? message : "")
                .data(user != null ? mapToUserResponse(user) : null)
                .timestamp(LocalDateTime.now())
                .build();
    }

    /**
     * Creates a generic error response with the specified status and message
     *
     * @param status  HTTP status code
     * @param message Error message
     * @return ErrorResponse with status information
     */
    public static ErrorResponse mapToErrorResponse(int status, String message) {
        return ErrorResponse.builder()
                .status(status)
                .message(message != null ? message : "An error occurred")
                .timestamp(LocalDateTime.now())
                .build();
    }

    /**
     * Creates a generic response with the specified status and message
     *
     * @param status  HTTP status code
     * @param message Response message
     * @return GenericResponse with status information
     */
    public static GenericResponse mapToGenericResponse(int status, String message) {
        return GenericResponse.builder()
                .status(status)
                .message(message != null ? message : "")
                .timestamp(LocalDateTime.now())
                .build();
    }

    /**
     * Creates an email verification response
     *
     * @param success Whether the operation was successful
     * @param message Response message
     * @return EmailVerificationResponse with status information
     */
    public static EmailVerificationResponse mapToEmailVerificationResponse(boolean success, String message) {
        return new EmailVerificationResponse(
                success,
                message != null ? message : "",
                LocalDateTime.now()
        );
    }
} 