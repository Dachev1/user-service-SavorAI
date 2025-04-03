package dev.idachev.userservice.config;

import dev.idachev.userservice.model.Role;
import dev.idachev.userservice.model.User;
import dev.idachev.userservice.repository.UserRepository;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Profile;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Initializes test data for integration tests.
 * Only active in the "test" profile.
 */
@Component
@Profile("test")
public class TestDataInitializer {
    
    // Replace @Slf4j with a manual logger declaration
    private static final Logger log = LoggerFactory.getLogger(TestDataInitializer.class);

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    
    // Replace @RequiredArgsConstructor with an explicit constructor
    public TestDataInitializer(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    /**
     * User IDs for commonly used test users
     */
    public static final UUID ADMIN_USER_ID = UUID.fromString("11111111-1111-1111-1111-111111111111");
    public static final UUID REGULAR_USER_ID = UUID.fromString("22222222-2222-2222-2222-222222222222");
    public static final UUID BANNED_USER_ID = UUID.fromString("33333333-3333-3333-3333-333333333333");
    public static final UUID UNVERIFIED_USER_ID = UUID.fromString("44444444-4444-4444-4444-444444444444");

    /**
     * Initializes test data after app context is ready
     */
    @PostConstruct
    @Transactional
    public void initializeTestData() {
        log.info("Initializing test data");
        
        // Only create data if repository is empty
        if (userRepository.count() > 0) {
            log.info("Test data already exists, skipping initialization");
            return;
        }

        // Create test users
        createAdminUser();
        createRegularUser();
        createBannedUser();
        createUnverifiedUser();
        
        log.info("Test data initialization completed");
    }

    private void createAdminUser() {
        User admin = new User();
        admin.setId(ADMIN_USER_ID);
        admin.setUsername("admin");
        admin.setEmail("admin@example.com");
        admin.setPassword(passwordEncoder.encode("Password123!"));
        admin.setRole(Role.ADMIN);
        admin.setBanned(false);
        admin.setEnabled(true);
        admin.setVerificationToken(null);
        admin.setCreatedOn(LocalDateTime.now());
        admin.setUpdatedOn(LocalDateTime.now());
        userRepository.save(admin);
        log.info("Created admin user: {}", admin.getUsername());
    }

    private void createRegularUser() {
        User user = new User();
        user.setId(REGULAR_USER_ID);
        user.setUsername("user");
        user.setEmail("user@example.com");
        user.setPassword(passwordEncoder.encode("Password123!"));
        user.setRole(Role.USER);
        user.setBanned(false);
        user.setEnabled(true);
        user.setVerificationToken(null);
        user.setCreatedOn(LocalDateTime.now());
        user.setUpdatedOn(LocalDateTime.now());
        userRepository.save(user);
        log.info("Created regular user: {}", user.getUsername());
    }

    private void createBannedUser() {
        User banned = new User();
        banned.setId(BANNED_USER_ID);
        banned.setUsername("banned");
        banned.setEmail("banned@example.com");
        banned.setPassword(passwordEncoder.encode("Password123!"));
        banned.setRole(Role.USER);
        banned.setBanned(true);
        banned.setEnabled(true);
        banned.setVerificationToken(null);
        banned.setCreatedOn(LocalDateTime.now());
        banned.setUpdatedOn(LocalDateTime.now());
        userRepository.save(banned);
        log.info("Created banned user: {}", banned.getUsername());
    }

    private void createUnverifiedUser() {
        User unverified = new User();
        unverified.setId(UNVERIFIED_USER_ID);
        unverified.setUsername("unverified");
        unverified.setEmail("unverified@example.com");
        unverified.setPassword(passwordEncoder.encode("Password123!"));
        unverified.setRole(Role.USER);
        unverified.setBanned(false);
        unverified.setEnabled(false);
        unverified.setVerificationToken("test-verification-token");
        unverified.setCreatedOn(LocalDateTime.now());
        unverified.setUpdatedOn(LocalDateTime.now());
        userRepository.save(unverified);
        log.info("Created unverified user: {}", unverified.getUsername());
    }
} 