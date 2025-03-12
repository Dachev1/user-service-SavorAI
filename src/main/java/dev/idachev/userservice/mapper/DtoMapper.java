package dev.idachev.userservice.mapper;

import dev.idachev.userservice.model.User;
import dev.idachev.userservice.web.dto.AuthResponse;
import dev.idachev.userservice.web.dto.UserResponse;
import dev.idachev.userservice.web.dto.VerificationResponse;

public final class DtoMapper {

    private DtoMapper() {
        throw new UnsupportedOperationException("This is a utility class and cannot be instantiated");
    }

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
     * Maps a User entity to AuthResponse DTO
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
        // User can be null here for failed verification responses
        UserResponse userData = user != null ? mapToUserResponse(user) : null;

        return VerificationResponse.builder()
                .success(success)
                .message(message != null ? message : "")
                .data(userData)
                .build();
    }
} 