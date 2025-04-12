package dev.idachev.userservice.mapper;

import dev.idachev.userservice.model.User;
import dev.idachev.userservice.web.dto.AuthResponse;
import dev.idachev.userservice.web.dto.GenericResponse;
import dev.idachev.userservice.web.dto.UserResponse;
import dev.idachev.userservice.web.dto.VerificationResponse;
import lombok.experimental.UtilityClass;

import java.time.LocalDateTime;
import java.util.Optional;

/**
 * Utility class for mapping between entities and DTOs
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
        validateUser(user, "Cannot map null user to UserResponse");

        return UserResponse.builder()
                .id(user.getId())
                .username(user.getUsername())
                .email(user.getEmail())
                .role(user.getRole().name())
                .banned(user.isBanned())
                .verified(user.isEnabled())
                .verificationPending(user.isVerificationPending())
                .createdOn(user.getCreatedOn())
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
        validateUser(user, "Cannot map null user to AuthResponse");

        UserResponse userResponse = mapToUserResponse(user);

        return AuthResponse.builder()
                .token(Optional.ofNullable(token).orElse(""))
                .username(user.getUsername())
                .email(user.getEmail())
                .role(user.getRole().name())
                .verified(user.isEnabled())
                .verificationPending(user.isVerificationPending())
                .banned(user.isBanned())
                .lastLogin(user.getLastLogin())
                .success(true)
                .message("")
                .user(userResponse)
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
                .banned(user.isBanned())
                .lastLogin(user.getLastLogin())
                .success(success)
                .message(getNonNullMessage(message))
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
                .message(getNonNullMessage(message))
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
                .message(getNonNullMessage(message))
                .data(user != null ? mapToUserResponse(user) : null)
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
                .message(getNonNullMessage(message))
                .timestamp(LocalDateTime.now())
                .build();
    }

    /**
     * Validates that a user is not null
     */
    private static void validateUser(User user, String errorMessage) {
        if (user == null) {
            throw new IllegalArgumentException(errorMessage);
        }
    }

    /**
     * Returns a non-null message
     */
    private static String getNonNullMessage(String message) {
        return message != null ? message : "";
    }
} 