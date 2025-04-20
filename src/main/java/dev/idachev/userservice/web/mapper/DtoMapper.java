package dev.idachev.userservice.web.mapper;

import dev.idachev.userservice.model.User;
import dev.idachev.userservice.web.dto.AuthResponse;
import dev.idachev.userservice.web.dto.GenericResponse;
import dev.idachev.userservice.web.dto.UserResponse;
import dev.idachev.userservice.web.dto.VerificationResponse;
import lombok.experimental.UtilityClass;

import java.time.LocalDateTime;
import java.util.Objects;

/**
 * Maps entities to DTOs
 */
@UtilityClass
public class DtoMapper {

    /**
     * Maps User entity to UserResponse DTO
     */
    public static UserResponse mapToUserResponse(User user) {
        Objects.requireNonNull(user, "Cannot map null user to UserResponse");

        return UserResponse.builder()
                .id(user.getId())
                .username(user.getUsername())
                .email(user.getEmail())
                .role(user.getRole().name())
                .banned(user.isBanned())
                .enabled(user.isEnabled())
                .verificationPending(user.isVerificationPending())
                .createdOn(user.getCreatedOn())
                .lastLogin(user.getLastLogin())
                .build();
    }

    /**
     * Maps User entity to AuthResponse DTO with token
     */
    public static AuthResponse mapToAuthResponse(User user, String token) {
        Objects.requireNonNull(user, "Cannot map null user to AuthResponse");
        
        // Ensure token is never null
        String safeToken = token != null ? token : "";

        return AuthResponse.builder()
                .token(safeToken)
                .username(user.getUsername())
                .email(user.getEmail())
                .role(user.getRole().name())
                .enabled(user.isEnabled())
                .verificationPending(user.isVerificationPending())
                .banned(user.isBanned())
                .lastLogin(user.getLastLogin())
                .success(true)
                .message("")
                .user(mapToUserResponse(user))
                .build();
    }

    /**
     * Creates an AuthResponse with success status and user info
     */
    public static AuthResponse mapToAuthResponse(User user, boolean success, String message) {
        if (user == null) {
            return mapToAuthResponse(success, message);
        }

        return AuthResponse.builder()
                .username(user.getUsername())
                .email(user.getEmail())
                .role(user.getRole().name())
                .token("")  // Empty token by default
                .enabled(user.isEnabled())
                .verificationPending(user.isVerificationPending())
                .banned(user.isBanned())
                .lastLogin(user.getLastLogin())
                .success(success)
                .message(message != null ? message : "")
                .user(mapToUserResponse(user))
                .build();
    }

    /**
     * Creates a simple AuthResponse with just status and message
     */
    public static AuthResponse mapToAuthResponse(boolean success, String message) {
        return AuthResponse.builder()
                .success(success)
                .message(message != null ? message : "")
                .token("")  // Ensure token is not null
                .username("")  // Ensure username is not null
                .email("")  // Ensure email is not null
                .role("")  // Ensure role is not null
                .build();
    }

    /**
     * Maps User entity to a VerificationResponse DTO
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
     * Creates a generic response with status and message
     */
    public static GenericResponse mapToGenericResponse(int status, String message) {
        return GenericResponse.builder()
                .status(status)
                .message(message != null ? message : "")
                .timestamp(LocalDateTime.now())
                .success(status >= 200 && status < 300)  // Set success based on HTTP status code
                .build();
    }
} 