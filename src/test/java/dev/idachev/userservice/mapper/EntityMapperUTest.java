package dev.idachev.userservice.mapper;

import dev.idachev.userservice.model.User;
import dev.idachev.userservice.web.dto.RegisterRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.LocalDateTime;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class EntityMapperUTest {

    @Mock
    private PasswordEncoder passwordEncoder;

    private RegisterRequest validRequest;
    private String testUsername;
    private String testEmail;
    private String testPassword;
    private String encodedPassword;
    private String verificationToken;

    @BeforeEach
    void setUp() {
        testUsername = "testUser";
        testEmail = "test@example.com";
        testPassword = "password123";
        encodedPassword = "encoded_password";
        verificationToken = UUID.randomUUID().toString();

        validRequest = RegisterRequest.builder()
                .username(testUsername)
                .email(testEmail)
                .password(testPassword)
                .build();
    }

    @Test
    void givenValidRequest_whenMapToNewUser_thenReturnUserEntityWithRawPassword() {

        // When
        User result = EntityMapper.mapToNewUser(validRequest);

        // Then
        assertNotNull(result);
        assertEquals(testUsername, result.getUsername());
        assertEquals(testEmail, result.getEmail());
        assertEquals(testPassword, result.getPassword()); // Password not encoded
        assertFalse(result.isEnabled());
        assertNull(result.getVerificationToken());
        assertNotNull(result.getCreatedOn());
        assertNotNull(result.getUpdatedOn());
        assertEquals(result.getCreatedOn(), result.getUpdatedOn());
    }

    @Test
    void givenNullRequest_whenMapToNewUser_thenThrowIllegalArgumentException() {

        // When & Then
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> EntityMapper.mapToNewUser(null)
        );

        assertEquals("Cannot map null request to User", exception.getMessage());
    }

    @Test
    void givenValidRequestWithEncoderAndToken_whenMapToNewUser_thenReturnFullyConfiguredUser() {

        // Given
        when(passwordEncoder.encode(anyString())).thenReturn(encodedPassword);

        // When
        User result = EntityMapper.mapToNewUser(validRequest, passwordEncoder, verificationToken);

        // Then
        assertNotNull(result);
        assertEquals(testUsername, result.getUsername());
        assertEquals(testEmail, result.getEmail());
        assertEquals(encodedPassword, result.getPassword()); // Password encoded
        assertFalse(result.isEnabled());
        assertEquals(verificationToken, result.getVerificationToken());
        assertNotNull(result.getCreatedOn());
        assertNotNull(result.getUpdatedOn());

        // Verify that the password encoder was called
        verify(passwordEncoder).encode(testPassword);
    }

    @Test
    void givenNullRequestWithEncoderAndToken_whenMapToNewUser_thenThrowIllegalArgumentException() {

        // When & Then
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> EntityMapper.mapToNewUser(null, passwordEncoder, verificationToken)
        );

        assertEquals("Cannot map null request to User", exception.getMessage());
    }

    @Test
    void whenMapToNewUser_thenSetsCorrectTimestamps() {

        // Given
        LocalDateTime beforeOperation = LocalDateTime.now();

        // When
        User result = EntityMapper.mapToNewUser(validRequest);

        // Record time after operation
        LocalDateTime afterOperation = LocalDateTime.now();

        // Then
        assertNotNull(result.getCreatedOn());
        assertNotNull(result.getUpdatedOn());

        // The creation timestamp should be between beforeOperation and afterOperation
        assertTrue(
                !result.getCreatedOn().isBefore(beforeOperation.minusSeconds(1)) &&
                        !result.getCreatedOn().isAfter(afterOperation.plusSeconds(1)),
                "Creation timestamp should be between test execution bounds"
        );

        // Created and updated should be the same in a new entity
        assertEquals(result.getCreatedOn(), result.getUpdatedOn());
    }

    @Test
    void whenMapToNewUser_thenSetsCorrectDefaultValues() {

        // When
        User result = EntityMapper.mapToNewUser(validRequest);

        // Then
        assertFalse(result.isEnabled());
        assertNull(result.getId());
        assertNull(result.getVerificationToken());
        assertNull(result.getLastLogin());
        assertFalse(result.isLoggedIn());
    }

    @Test
    void givenEncoderAndToken_whenMapToNewUser_thenSetsCorrectDefaultValues() {

        // Given
        when(passwordEncoder.encode(anyString())).thenReturn(encodedPassword);

        // When
        User result = EntityMapper.mapToNewUser(validRequest, passwordEncoder, verificationToken);

        // Then
        assertFalse(result.isEnabled());
        assertNull(result.getId());
        assertNull(result.getLastLogin());
        assertFalse(result.isLoggedIn());
    }
} 