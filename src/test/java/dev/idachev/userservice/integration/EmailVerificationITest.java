package dev.idachev.userservice.integration;

import dev.idachev.userservice.model.Role;
import dev.idachev.userservice.model.User;
import dev.idachev.userservice.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.LocalDateTime;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(MockitoExtension.class)
public class EmailVerificationITest {

    @Mock
    private UserRepository userRepository;
    
    @Test
    void testVerificationToken() {
        // Create a test user with verification token
        String verificationToken = UUID.randomUUID().toString();
        User user = User.builder()
                .id(UUID.randomUUID())
                .username("verifyuser")
                .email("verify@example.com")
                .password("password")
                .role(Role.USER)
                .enabled(false)
                .verificationToken(verificationToken)
                .createdOn(LocalDateTime.now())
                .build();
        
        // Verify user has the expected properties
        assertThat(user.getId()).isNotNull();
        assertThat(user.getVerificationToken()).isEqualTo(verificationToken);
        assertThat(user.isEnabled()).isFalse();
    }
} 