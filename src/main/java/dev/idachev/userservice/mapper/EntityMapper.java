package dev.idachev.userservice.mapper;

import dev.idachev.userservice.model.Role;
import dev.idachev.userservice.model.User;
import dev.idachev.userservice.web.dto.RegisterRequest;
import lombok.experimental.UtilityClass;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.LocalDateTime;
import java.util.Objects;

/**
 * Maps DTOs to entities
 */
@UtilityClass
public class EntityMapper {

    /**
     * Maps RegisterRequest to a new User entity
     */
    public static User mapToNewUser(RegisterRequest request) {
        Objects.requireNonNull(request, "Cannot map null request to User");

        LocalDateTime now = LocalDateTime.now();

        return User.builder()
                .username(request.getUsername())
                .email(request.getEmail())
                .password(request.getPassword()) // Not encoded yet
                .role(Role.USER)
                .enabled(false)
                .banned(false)
                .createdOn(now)
                .updatedOn(now)
                .build();
    }

    /**
     * Maps RegisterRequest to a new User with encoded password and verification token
     */
    public static User mapToNewUser(RegisterRequest request, PasswordEncoder passwordEncoder,
                                   String verificationToken) {
        User user = mapToNewUser(request);
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setVerificationToken(verificationToken);

        return user;
    }
} 