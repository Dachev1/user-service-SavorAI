package dev.idachev.userservice.config;

import org.junit.jupiter.api.TestInstance;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.annotation.Transactional;

/**
 * Base class for all integration tests.
 * Provides common configuration and setup for integration tests.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Transactional
public abstract class BaseIntegrationTest {

    /**
     * Configure dynamic properties for tests.
     * This is useful for overriding properties at runtime.
     */
    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        // You can add dynamic properties here if needed
        // Example: registry.add("spring.datasource.url", () -> "jdbc:h2:mem:testdb-" + UUID.randomUUID());
    }
} 