package dev.idachev.userservice.mapper;

import dev.idachev.userservice.model.User;
import dev.idachev.userservice.web.dto.RegisterRequest;
import lombok.experimental.UtilityClass;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.LocalDateTime;


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
     * @param request           the registration request
     * @param passwordEncoder   encoder for the password
     * @param verificationToken token for email verification
     * @return a new User entity with encoded password and verification token
     * @throws IllegalArgumentException if request is null
     */
    public static User mapToNewUser(RegisterRequest request, PasswordEncoder passwordEncoder,
                                    String verificationToken) {
        // Fix infinite recursion by NOT calling self with same parameters
        // First get the basic user without encoded password
        User user = mapToNewUser(request);
        
        // Then encode the password and set the verification token
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setVerificationToken(verificationToken);
        
        return user;
    }
} 