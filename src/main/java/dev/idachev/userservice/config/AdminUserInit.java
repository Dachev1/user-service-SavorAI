package dev.idachev.userservice.config;

import dev.idachev.userservice.model.Role;
import dev.idachev.userservice.model.User;
import dev.idachev.userservice.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;

/**
 * Initializes admin user on application startup if it doesn't exist
 */
@Component
@Slf4j
public class AdminUserInit implements CommandLineRunner {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Autowired
    public AdminUserInit(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void run(String... args) {
        String username = "Ivan";
        String email = "pffe3e@gmail.com";

        // Check if user already exists
        if (userRepository.existsByUsername(username) || userRepository.existsByEmail(email)) {
            log.info("Admin user '{}' already exists, skipping initialization", username);
            return;
        }

        // Create admin user
        User adminUser = User.builder()
                .username(username)
                .email(email)
                .password(passwordEncoder.encode("123456789"))
                .role(Role.ADMIN)
                .enabled(true) // Pre-verified
                .createdOn(LocalDateTime.now())
                .updatedOn(LocalDateTime.now())
                .build();

        userRepository.save(adminUser);
        log.info("Admin user '{}' created successfully", username);
    }
} 