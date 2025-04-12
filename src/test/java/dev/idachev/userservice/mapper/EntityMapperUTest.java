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

    // Test data
    private RegisterRequest validRequest;
    private String testUsername;
    private String testEmail;
    private String testPassword;
    private String encodedPassword;
    private String verificationToken;

    @BeforeEach
    void setUp() {
        // Given
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
    void mapToNewUser_validRequest_returnsUserWithRawPassword() {
        // Given - setup in setUp()

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
    void mapToNewUser_nullRequest_throwsIllegalArgumentException() {
        // Given
        RegisterRequest nullRequest = null;

        // When & Then
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> EntityMapper.mapToNewUser(nullRequest)
        );

        assertEquals("Cannot map null request to User", exception.getMessage());
    }

    @Test
    void mapToNewUser_validRequestWithEncoderAndToken_returnsFullyConfiguredUser() {
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
        verify(passwordEncoder).encode(testPassword);
    }

    @Test
    void mapToNewUser_nullRequestWithEncoderAndToken_throwsIllegalArgumentException() {
        // Given
        RegisterRequest nullRequest = null;

        // When & Then
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> EntityMapper.mapToNewUser(nullRequest, passwordEncoder, verificationToken)
        );

        assertEquals("Cannot map null request to User", exception.getMessage());
    }

    @Test
    void mapToNewUser_anyRequest_setsCorrectTimestamps() {
        // Given - setup in setUp()

        // When
        User result = EntityMapper.mapToNewUser(validRequest);

        // Then
        assertNotNull(result.getCreatedOn());
        assertNotNull(result.getUpdatedOn());
        assertEquals(result.getCreatedOn(), result.getUpdatedOn());
    }

    @Test
    void mapToNewUser_validRequest_setsCorrectDefaultValues() {
        // Given - setup in setUp()

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
    void mapToNewUser_validRequestWithEncoderAndToken_setsCorrectDefaultValues() {
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