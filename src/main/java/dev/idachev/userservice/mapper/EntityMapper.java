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
     * Maps RegisterRequest to a new User entity with an encoded password.
     *
     * @param request         The registration request DTO.
     * @param passwordEncoder The password encoder service.
     * @param verificationToken The verification token to associate with the user.
     * @return A new User entity, not yet persisted.
     */
    public static User mapToNewUser(RegisterRequest request, PasswordEncoder passwordEncoder, String verificationToken) {
        Objects.requireNonNull(request, "Cannot map null request to User");
        Objects.requireNonNull(passwordEncoder, "PasswordEncoder cannot be null");
        Objects.requireNonNull(verificationToken, "Verification token cannot be null");

        LocalDateTime now = LocalDateTime.now();

        return User.builder()
                .username(request.username())
                .email(request.email())
                .password(passwordEncoder.encode(request.password()))
                .role(Role.USER)
                .enabled(false)
                .banned(false)
                .createdOn(now)
                .updatedOn(now)
                .verificationToken(verificationToken)
                .build();
    }
} 