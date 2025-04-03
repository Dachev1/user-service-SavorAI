//package dev.idachev.userservice.service;
//
//import dev.idachev.userservice.exception.ResourceNotFoundException;
//import dev.idachev.userservice.model.User;
//import dev.idachev.userservice.repository.UserRepository;
//import dev.idachev.userservice.security.UserPrincipal;
//import dev.idachev.userservice.web.dto.AuthResponse;
//import dev.idachev.userservice.web.dto.EmailVerificationResponse;
//import dev.idachev.userservice.web.dto.VerificationResponse;
//import dev.idachev.userservice.web.dto.VerificationResult;
//import org.junit.jupiter.api.BeforeEach;
//import org.junit.jupiter.api.Test;
//import org.junit.jupiter.api.extension.ExtendWith;
//import org.mockito.InjectMocks;
//import org.mockito.Mock;
//import org.mockito.junit.jupiter.MockitoExtension;
//
//import java.time.LocalDateTime;
//import java.util.Optional;
//import java.util.UUID;
//import java.util.concurrent.CompletableFuture;
//
//import static org.junit.jupiter.api.Assertions.*;
//import static org.mockito.ArgumentMatchers.any;
//import static org.mockito.ArgumentMatchers.anyString;
//import static org.mockito.ArgumentMatchers.eq;
//import static org.mockito.Mockito.*;
//
//@ExtendWith(MockitoExtension.class)
//class VerificationServiceUTest {
//
//    @Mock
//    private UserRepository userRepository;
//
//    @Mock
//    private EmailService emailService;
//
//    @Mock
//    private TokenService tokenService;
//
//    @InjectMocks
//    private VerificationService verificationService;
//
//    private User testUser;
//    private String testToken;
//
//    @BeforeEach
//    void setUp() {
//        testUser = new User();
//        testUser.setId(UUID.randomUUID());
//        testUser.setUsername("testuser");
//        testUser.setEmail("test@example.com");
//        testUser.setVerificationToken(UUID.randomUUID().toString());
//        testUser.setEnabled(false);
//        testUser.setUpdatedOn(LocalDateTime.now());
//
//        testToken = testUser.getVerificationToken();
//    }
//
//    @Test
//    void verifyEmail_WithValidToken_ReturnsTrue() {
//        // Given
//        when(userRepository.findByVerificationToken(anyString())).thenReturn(Optional.of(testUser));
//        when(userRepository.save(any(User.class))).thenReturn(testUser);
//
//        // When
//        boolean result = verificationService.verifyEmail(testToken);
//
//        // Then
//        assertTrue(result);
//        assertTrue(testUser.isEnabled());
//        assertNull(testUser.getVerificationToken());
//        verify(userRepository).save(testUser);
//    }
//
//    @Test
//    void verifyEmail_WithInvalidToken_ThrowsException() {
//        // Given
//        when(userRepository.findByVerificationToken(anyString())).thenReturn(Optional.empty());
//
//        // When/Then
//        assertThrows(ResourceNotFoundException.class, () ->
//            verificationService.verifyEmail(testToken));
//    }
//
//    @Test
//    void verifyEmail_WithAlreadyVerifiedUser_ReturnsTrue() {
//        // Given
//        testUser.setEnabled(true);
//        when(userRepository.findByVerificationToken(anyString())).thenReturn(Optional.of(testUser));
//
//        // When
//        boolean result = verificationService.verifyEmail(testToken);
//
//        // Then
//        assertTrue(result);
//        verify(userRepository, never()).save(any(User.class));
//    }
//
//    @Test
//    void verifyEmailAndGetResponse_WithValidToken_ReturnsSuccess() {
//        // Given
//        when(userRepository.findByVerificationToken(anyString())).thenReturn(Optional.of(testUser));
//        when(userRepository.save(any(User.class))).thenReturn(testUser);
//
//        // When
//        VerificationResponse response = verificationService.verifyEmailAndGetResponse(testToken);
//
//        // Then
//        assertNotNull(response);
//        assertTrue(response.isSuccess());
//        assertTrue(response.getMessage().contains("verified successfully"));
//    }
//
//    @Test
//    void verifyEmailAndGetResponse_InvalidToken_ThrowsResourceNotFoundException() {
//        // Given
//        String invalidToken = "invalid_token";
//        when(userRepository.findByVerificationToken(invalidToken)).thenReturn(Optional.empty());
//
//        // When/Then
//        assertThrows(ResourceNotFoundException.class, () -> {
//            verificationService.verifyEmailAndGetResponse(invalidToken);
//        });
//    }
//
//    @Test
//    void resendVerificationEmail_WithValidEmail_ReturnsTrue() {
//        // Given
//        // Set the token to null to force regeneration
//        testUser.setVerificationToken(null);
//
//        // Generate new token when requested
//        String newToken = UUID.randomUUID().toString();
//        when(emailService.generateVerificationToken()).thenReturn(newToken);
//
//        // Mock repository responses
//        when(userRepository.findByEmail(eq("test@example.com"))).thenReturn(Optional.of(testUser));
//        when(userRepository.save(any(User.class))).thenAnswer(invocation -> {
//            User savedUser = invocation.getArgument(0);
//            // This assertion verifies the user's token was updated
//            assertEquals(newToken, savedUser.getVerificationToken());
//            return savedUser;
//        });
//
//        // Mock email sending
//        when(emailService.sendVerificationEmailAsync(any(User.class)))
//            .thenReturn(CompletableFuture.completedFuture(null));
//
//        // When
//        boolean result = verificationService.resendVerificationEmail(testUser.getEmail());
//
//        // Then
//        assertTrue(result);
//        assertEquals(newToken, testUser.getVerificationToken());
//        verify(userRepository).save(any(User.class));
//        verify(emailService).sendVerificationEmailAsync(testUser);
//    }
//
//    @Test
//    void resendVerificationEmail_WithNonexistentEmail_ReturnsFalse() {
//        // Given
//        when(userRepository.findByEmail(anyString())).thenReturn(Optional.empty());
//
//        // When
//        boolean result = verificationService.resendVerificationEmail("nonexistent@example.com");
//
//        // Then
//        assertFalse(result);
//    }
//
//    @Test
//    void resendVerificationEmail_WithVerifiedUser_ReturnsFalse() {
//        // Given
//        testUser.setEnabled(true);
//        when(userRepository.findByEmail(anyString())).thenReturn(Optional.of(testUser));
//
//        // When
//        boolean result = verificationService.resendVerificationEmail(testUser.getEmail());
//
//        // Then
//        assertFalse(result);
//        verify(userRepository, never()).save(any(User.class));
//    }
//
//    @Test
//    void resendVerificationEmailWithResponse_WithValidEmail_ReturnsSuccess() {
//        // Given
//        // Setup so the underlying resendVerificationEmail method returns true
//        testUser.setVerificationToken(null);
//        String newToken = UUID.randomUUID().toString();
//        when(emailService.generateVerificationToken()).thenReturn(newToken);
//        when(userRepository.findByEmail(eq("test@example.com"))).thenReturn(Optional.of(testUser));
//        when(userRepository.save(any(User.class))).thenReturn(testUser);
//        when(emailService.sendVerificationEmailAsync(any(User.class)))
//            .thenReturn(CompletableFuture.completedFuture(null));
//
//        // When
//        EmailVerificationResponse response = verificationService.resendVerificationEmailWithResponse(testUser.getEmail());
//
//        // Then
//        assertNotNull(response);
//        assertTrue(response.isSuccess());
//        assertTrue(response.getMessage().contains("has been resent"));
//
//        // Verify that the underlying dependencies were called correctly
//        verify(userRepository).findByEmail(eq("test@example.com"));
//        verify(userRepository).save(any(User.class));
//        verify(emailService).sendVerificationEmailAsync(any(User.class));
//    }
//
//    @Test
//    void getVerificationStatus_WithUnverifiedUser_ReturnsUnverified() {
//        // Given
//        when(userRepository.findByEmail(anyString())).thenReturn(Optional.of(testUser));
//
//        // When
//        AuthResponse response = verificationService.getVerificationStatus(testUser.getEmail());
//
//        // Then
//        assertNotNull(response);
//        assertFalse(response.isVerified());
//        assertTrue(response.getToken().isEmpty());
//    }
//
//    @Test
//    void getVerificationStatus_WithVerifiedUser_ReturnsVerifiedWithToken() {
//        // Given
//        testUser.setEnabled(true);
//        String token = "test.jwt.token";
//        when(userRepository.findByEmail(anyString())).thenReturn(Optional.of(testUser));
//        when(tokenService.generateToken(any(UserPrincipal.class))).thenReturn(token);
//
//        // When
//        AuthResponse response = verificationService.getVerificationStatus(testUser.getEmail());
//
//        // Then
//        assertNotNull(response);
//        assertTrue(response.isVerified());
//        assertEquals(token, response.getToken());
//    }
//
//    @Test
//    void verifyEmailForRedirect_WithValidToken_ReturnsSuccess() {
//        // Given
//        when(userRepository.findByVerificationToken(anyString())).thenReturn(Optional.of(testUser));
//        when(userRepository.save(any(User.class))).thenReturn(testUser);
//
//        // When
//        VerificationResult result = verificationService.verifyEmailForRedirect(testToken);
//
//        // Then
//        assertNotNull(result);
//        assertTrue(result.isSuccess());
//        assertNull(result.getErrorType());
//    }
//
//    @Test
//    void verifyEmailForRedirect_WithInvalidToken_ReturnsFailure() {
//        // Given
//        when(userRepository.findByVerificationToken(anyString())).thenReturn(Optional.empty());
//
//        // When
//        VerificationResult result = verificationService.verifyEmailForRedirect(testToken);
//
//        // Then
//        assertNotNull(result);
//        assertFalse(result.isSuccess());
//        assertEquals("ResourceNotFoundException", result.getErrorType());
//    }
//}