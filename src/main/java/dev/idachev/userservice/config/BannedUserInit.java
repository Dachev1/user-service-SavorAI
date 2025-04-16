package dev.idachev.userservice.config;

import dev.idachev.userservice.model.Role;
import dev.idachev.userservice.model.User;
import dev.idachev.userservice.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

/**
 * Initializes a banned user on application startup if it doesn't exist
 */
@Component
@Slf4j
public class BannedUserInit implements CommandLineRunner {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public BannedUserInit(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    @Transactional
    public void run(String... args) {
        String username = "TestBanned";
        String email = "testbanned@example.com";

        // Check if user already exists
        if (userRepository.existsByUsername(username) || userRepository.existsByEmail(email)) {
            log.info("Banned test user '{}' already exists, skipping initialization", username);
            return;
        }

        // Create banned user
        User bannedUser = User.builder()
                .username(username)
                .email(email)
                .password(passwordEncoder.encode("1234567890"))
                .role(Role.USER)
                .enabled(true) // Account is enabled
                .banned(true)  // But banned
                .createdOn(LocalDateTime.now())
                .updatedOn(LocalDateTime.now())
                .build();

        userRepository.save(bannedUser);
        log.info("Banned test user '{}' created successfully", username);
    }
} 