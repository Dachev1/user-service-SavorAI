package dev.idachev.userservice.mapper;

import dev.idachev.userservice.model.User;
import dev.idachev.userservice.web.dto.RegisterRequest;
import lombok.experimental.UtilityClass;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.LocalDateTime;

/**
 * Utility class for mapping between DTOs and domain entities
 * Handles the conversion from request objects to entity objects
 */
@UtilityClass
public final class EntityMapper {

    /**
     * Maps a RegisterRequest DTO to a new User entity
     * Note: This does not set the verification token or encode the password
     * 
     * @param request the registration request
     * @return a new User entity (not persisted)
     * @throws IllegalArgumentException if request is null
     */
    public static User mapToNewUser(RegisterRequest request) {
        if (request == null) {
            throw new IllegalArgumentException("Cannot map null request to User");
        }
        
        LocalDateTime now = LocalDateTime.now();
        
        return User.builder()
                .username(request.getUsername())
                .email(request.getEmail())
                .password(request.getPassword()) // Not encoded yet
                .enabled(false)
                .createdOn(now)
                .updatedOn(now)
                .build();
    }
    
    /**
     * Maps a RegisterRequest DTO to a new User entity with encoded password and verification token
     * 
     * @param request the registration request
     * @param passwordEncoder encoder for the password
     * @param verificationToken token for email verification
     * @return a new User entity with encoded password and verification token
     * @throws IllegalArgumentException if request is null
     */
    public static User mapToNewUser(RegisterRequest request, PasswordEncoder passwordEncoder, String verificationToken) {
        if (request == null) {
            throw new IllegalArgumentException("Cannot map null request to User");
        }
        
        LocalDateTime now = LocalDateTime.now();
        
        return User.builder()
                .username(request.getUsername())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .verificationToken(verificationToken)
                .enabled(false)
                .createdOn(now)
                .updatedOn(now)
                .build();
    }
} 