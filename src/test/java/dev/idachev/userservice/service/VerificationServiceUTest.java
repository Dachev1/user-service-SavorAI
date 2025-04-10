package dev.idachev.userservice.service;

import dev.idachev.userservice.exception.ResourceNotFoundException;
import dev.idachev.userservice.model.User;
import dev.idachev.userservice.repository.UserRepository;
import dev.idachev.userservice.security.UserPrincipal;
import dev.idachev.userservice.web.dto.AuthResponse;
import dev.idachev.userservice.web.dto.GenericResponse;
import dev.idachev.userservice.web.dto.VerificationResponse;
import dev.idachev.userservice.web.dto.VerificationResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class VerificationServiceUTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private EmailService emailService;

    @Mock
    private TokenService tokenService;

    @InjectMocks
    private VerificationService verificationService;

    private User testUser;
    private String testToken;

    @BeforeEach
    void setUp() {
        testUser = new User();
        testUser.setId(UUID.randomUUID());
        testUser.setUsername("testuser");
        testUser.setEmail("test@example.com");
        testUser.setVerificationToken(UUID.randomUUID().toString());
        testUser.setEnabled(false);
        testUser.setUpdatedOn(LocalDateTime.now());

        testToken = testUser.getVerificationToken();
    }

    @Test
    void verifyEmail_WithValidToken_ReturnsTrue() {
        // Given
        when(userRepository.findByVerificationToken(anyString())).thenReturn(Optional.of(testUser));
        when(userRepository.save(any(User.class))).thenReturn(testUser);

        // When
        boolean result = verificationService.verifyEmail(testToken);

        // Then
        assertTrue(result);
        assertTrue(testUser.isEnabled());
        assertNull(testUser.getVerificationToken());
        verify(userRepository).save(testUser);
    }

    @Test
    void verifyEmail_WithInvalidToken_ThrowsException() {
        // Given
        when(userRepository.findByVerificationToken(anyString())).thenReturn(Optional.empty());

        // When/Then
        assertThrows(ResourceNotFoundException.class, () ->
            verificationService.verifyEmail(testToken));
    }

    @Test
    void verifyEmail_WithAlreadyVerifiedUser_ReturnsTrue() {
        // Given
        testUser.setEnabled(true);
        when(userRepository.findByVerificationToken(anyString())).thenReturn(Optional.of(testUser));

        // When
        boolean result = verificationService.verifyEmail(testToken);

        // Then
        assertTrue(result);
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    void verifyEmailAndGetResponse_WithValidToken_ReturnsSuccess() {
        // Given
        when(userRepository.findByVerificationToken(anyString())).thenReturn(Optional.of(testUser));
        when(userRepository.save(any(User.class))).thenReturn(testUser);

        // When
        VerificationResponse response = verificationService.verifyEmailAndGetResponse(testToken);

        // Then
        assertNotNull(response);
        assertTrue(response.isSuccess());
        assertTrue(response.getMessage().contains("verified successfully"));
    }

    @Test
    void verifyEmailAndGetResponse_InvalidToken_ThrowsResourceNotFoundException() {
        // Given
        String invalidToken = "invalid_token";
        when(userRepository.findByVerificationToken(invalidToken)).thenReturn(Optional.empty());

        // When/Then
        assertThrows(ResourceNotFoundException.class, () -> {
            verificationService.verifyEmailAndGetResponse(invalidToken);
        });
    }

    @Test
    void resendVerificationEmail_WithValidEmail_ReturnsSuccessResponse() {
        // Given
        // Set the token to null to force regeneration
        testUser.setVerificationToken(null);

        // Generate new token when requested
        String newToken = UUID.randomUUID().toString();
        when(emailService.generateVerificationToken()).thenReturn(newToken);

        // Mock repository responses
        when(userRepository.findByEmail(eq("test@example.com"))).thenReturn(Optional.of(testUser));
        when(userRepository.save(any(User.class))).thenReturn(testUser);

        // Mock email sending
        when(emailService.sendVerificationEmailAsync(any(User.class)))
            .thenReturn(CompletableFuture.completedFuture(null));

        // When
        GenericResponse response = verificationService.resendVerificationEmail(testUser.getEmail());

        // Then
        assertNotNull(response);
        assertTrue(response.isSuccess());
        assertTrue(response.getMessage().contains("has been resent"));
    }

    @Test
    void resendVerificationEmail_WithNonexistentEmail_ThrowsResourceNotFoundException() {
        // Given
        when(userRepository.findByEmail(anyString())).thenReturn(Optional.empty());

        // When/Then
        assertThrows(ResourceNotFoundException.class, () -> {
            verificationService.resendVerificationEmail("nonexistent@example.com");
        });
    }

    @Test
    void resendVerificationEmail_WithVerifiedUser_ReturnsFailureResponse() {
        // Given
        testUser.setEnabled(true);
        when(userRepository.findByEmail(anyString())).thenReturn(Optional.of(testUser));

        // When
        GenericResponse response = verificationService.resendVerificationEmail(testUser.getEmail());

        // Then
        assertNotNull(response);
        assertFalse(response.isSuccess());
        assertTrue(response.getMessage().contains("Failed"));
    }

    @Test
    void getVerificationStatus_ForUnverifiedUser_ReturnsUnverifiedStatus() {
        // Given
        when(userRepository.findByEmail(anyString())).thenReturn(Optional.of(testUser));

        // When
        AuthResponse response = verificationService.getVerificationStatus(testUser.getEmail());

        // Then
        assertNotNull(response);
        assertEquals(testUser.getEmail(), response.getEmail());
        assertFalse(response.isVerified());
        assertEquals("", response.getToken());
    }

    @Test
    void getVerificationStatus_ForVerifiedUser_ReturnsVerifiedStatusAndToken() {
        // Given
        testUser.setEnabled(true);
        when(userRepository.findByEmail(anyString())).thenReturn(Optional.of(testUser));

        String authToken = "jwt.token.string";
        when(tokenService.generateToken(any(UserPrincipal.class))).thenReturn(authToken);

        // When
        AuthResponse response = verificationService.getVerificationStatus(testUser.getEmail());

        // Then
        assertNotNull(response);
        assertEquals(testUser.getEmail(), response.getEmail());
        assertTrue(response.isVerified());
        assertEquals(authToken, response.getToken());
    }

    @Test
    void getVerificationStatus_WithNonexistentEmail_ThrowsResourceNotFoundException() {
        // Given
        when(userRepository.findByEmail(anyString())).thenReturn(Optional.empty());

        // When/Then
        assertThrows(ResourceNotFoundException.class, () -> {
            verificationService.getVerificationStatus("nonexistent@example.com");
        });
    }
    
    @Test
    void verifyEmailForRedirect_WithValidToken_ReturnsSuccess() {
        // Given
        when(userRepository.findByVerificationToken(anyString())).thenReturn(Optional.of(testUser));
        when(userRepository.save(any(User.class))).thenReturn(testUser);

        // When
        VerificationResult result = verificationService.verifyEmailForRedirect(testToken);

        // Then
        assertNotNull(result);
        assertTrue(result.isSuccess());
        assertNull(result.getErrorType());
    }

    @Test
    void verifyEmailForRedirect_WithInvalidToken_ReturnsFailure() {
        // Given
        when(userRepository.findByVerificationToken(anyString())).thenReturn(Optional.empty());

        // When
        VerificationResult result = verificationService.verifyEmailForRedirect(testToken);

        // Then
        assertNotNull(result);
        assertFalse(result.isSuccess());
        assertEquals("ResourceNotFoundException", result.getErrorType());
    }
}