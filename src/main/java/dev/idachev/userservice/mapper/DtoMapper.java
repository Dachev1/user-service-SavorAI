package dev.idachev.userservice.mapper;

import dev.idachev.userservice.model.User;
import dev.idachev.userservice.web.dto.AuthResponse;
import dev.idachev.userservice.web.dto.MessageResponse;
import dev.idachev.userservice.web.dto.UserResponse;
import dev.idachev.userservice.web.dto.VerificationResponse;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * Utility class for mapping between entity objects and DTOs (Data Transfer Objects).
 * 
 * This class centralizes all mapping operations to provide:
 * - Consistent mapping logic across the application
 * - Reduced code duplication
 * - Single point of maintenance for DTO transformations
 * 
 * All methods are static and should be called directly:
 * DtoMapper.mapToUserResponse(user)
 */
public final class DtoMapper {

    // Private constructor to prevent instantiation
    private DtoMapper() {
        throw new UnsupportedOperationException("This is a utility class and cannot be instantiated");
    }

    /**
     * Maps a User entity to UserResponse DTO
     * 
     * @param user the user entity to map
     * @return the UserResponse DTO or null if input is null
     */
    public static UserResponse mapToUserResponse(User user) {
        if (user == null) {
            return null;
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
     * @param user the user entity to map
     * @param token the JWT token (can be empty string for unverified users)
     * @return the AuthResponse DTO or null if input user is null
     */
    public static AuthResponse mapToAuthResponse(User user, String token) {
        if (user == null) {
            return null;
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
     * Creates a MessageResponse with success/failure status and message
     * 
     * @param success whether the operation was successful
     * @param message the message to include in the response
     * @return MessageResponse DTO
     */
    public static MessageResponse mapToMessageResponse(boolean success, String message) {
        return MessageResponse.builder()
                .success(success)
                .message(message != null ? message : "")
                .build();
    }
    
    /**
     * Maps a User entity to a VerificationResponse DTO
     * 
     * @param user the user entity (can be null)
     * @param success whether verification was successful
     * @param message the message to include in the response
     * @return the VerificationResponse DTO
     */
    public static VerificationResponse mapToVerificationResponse(User user, boolean success, String message) {
        // The VerificationResponse doesn't include user details directly
        // We can include user data as a UserResponse in the data field if needed
        UserResponse userData = user != null ? mapToUserResponse(user) : null;
        
        return VerificationResponse.builder()
                .success(success)
                .message(message != null ? message : "")
                .data(userData)
                .build();
    }
} 