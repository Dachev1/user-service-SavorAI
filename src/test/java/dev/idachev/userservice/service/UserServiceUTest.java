package dev.idachev.userservice.service;

import dev.idachev.userservice.exception.ResourceNotFoundException;
import dev.idachev.userservice.model.Role;
import dev.idachev.userservice.model.User;
import dev.idachev.userservice.repository.UserRepository;
import dev.idachev.userservice.web.dto.AuthResponse;
import dev.idachev.userservice.web.dto.GenericResponse;
import dev.idachev.userservice.web.dto.RegisterRequest;
import dev.idachev.userservice.web.dto.UserResponse;
import dev.idachev.userservice.web.dto.VerificationResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class UserServiceUTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private EmailService emailService;

    @InjectMocks
    private UserService userService;

    private RegisterRequest validRequest;
    private User mockUser;
    private String verificationToken;
    
    // Admin test variables
    private User regularUser;
    private User adminUser;
    private UUID regularUserId;

    @BeforeEach
    void setUp() {
        verificationToken = UUID.randomUUID().toString();
        regularUserId = UUID.randomUUID();

        validRequest = RegisterRequest.builder()
                .username("testuser")
                .email("test@example.com")
                .password("password123")
                .build();

        mockUser = User.builder()
                .username("testuser")
                .email("test@example.com")
                .password("encoded_password")
                .verificationToken(verificationToken)
                .enabled(false)
                .createdOn(LocalDateTime.now())
                .updatedOn(LocalDateTime.now())
                .build();
                
        // Initialize users for admin functionality tests
        regularUser = User.builder()
                .id(regularUserId)
                .username("user")
                .email("user@example.com")
                .password("password")
                .role(Role.USER)
                .enabled(true)
                .createdOn(LocalDateTime.now().minusDays(1))
                .build();
                
        adminUser = User.builder()
                .id(UUID.randomUUID())
                .username("admin")
                .email("admin@example.com")
                .password("password")
                .role(Role.ADMIN)
                .enabled(true)
                .createdOn(LocalDateTime.now().minusDays(2))
                .build();

        lenient().when(emailService.generateVerificationToken()).thenReturn(verificationToken);
        lenient().when(passwordEncoder.encode(anyString())).thenReturn("encoded_password");
    }

    @Test
    void givenValidRegistrationRequest_whenRegister_thenReturnSuccessResponse() {

        // Given
        when(userRepository.existsByUsername(anyString())).thenReturn(false);
        when(userRepository.existsByEmail(anyString())).thenReturn(false);
        when(userRepository.save(any(User.class))).thenReturn(mockUser);
        when(emailService.sendVerificationEmailAsync(any(User.class))).thenReturn(CompletableFuture.completedFuture(null));

        // When
        AuthResponse response = userService.register(validRequest);

        // Then
        assertNotNull(response);
        assertTrue(response.isSuccess());
        assertEquals("Registration successful! Please check your email to verify your account.", response.getMessage());

        verify(userRepository).existsByUsername(validRequest.getUsername());
        verify(userRepository).existsByEmail(validRequest.getEmail());
        verify(userRepository).save(any(User.class));
        verify(emailService).sendVerificationEmailAsync(any(User.class));
    }

    @Test
    void givenExistingUsername_whenRegister_thenReturnErrorResponse() {

        // Given
        when(userRepository.existsByUsername(validRequest.getUsername())).thenReturn(true);

        // When
        AuthResponse response = userService.register(validRequest);

        // Then
        assertNotNull(response);
        assertFalse(response.isSuccess());
        assertEquals("Username already exists", response.getMessage());

        verify(userRepository).existsByUsername(validRequest.getUsername());
        verify(userRepository, never()).save(any(User.class));
        verify(emailService, never()).sendVerificationEmailAsync(any(User.class));
    }

    @Test
    void givenExistingEmail_whenRegister_thenReturnErrorResponse() {

        // Given
        when(userRepository.existsByUsername(anyString())).thenReturn(false);
        when(userRepository.existsByEmail(validRequest.getEmail())).thenReturn(true);

        // When
        AuthResponse response = userService.register(validRequest);

        // Then
        assertNotNull(response);
        assertFalse(response.isSuccess());
        assertEquals("Email already exists", response.getMessage());

        verify(userRepository).existsByUsername(validRequest.getUsername());
        verify(userRepository).existsByEmail(validRequest.getEmail());
        verify(userRepository, never()).save(any(User.class));
        verify(emailService, never()).sendVerificationEmailAsync(any(User.class));
    }

    @Test
    void givenNullRequest_whenRegister_thenReturnErrorResponse() {

        // When
        AuthResponse response = userService.register(null);

        // Then
        assertNotNull(response);
        assertFalse(response.isSuccess());
        assertEquals("Registration request cannot be null", response.getMessage());

        verify(userRepository, never()).existsByUsername(anyString());
        verify(userRepository, never()).existsByEmail(anyString());
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    void givenRepositoryError_whenRegister_thenHandleErrorGracefully() {

        // Given
        when(userRepository.existsByUsername(anyString())).thenReturn(false);
        when(userRepository.existsByEmail(anyString())).thenReturn(false);
        when(userRepository.save(any(User.class))).thenThrow(new RuntimeException("Database error"));

        // When
        AuthResponse response = userService.register(validRequest);

        // Then
        assertNotNull(response);
        assertFalse(response.isSuccess());
        assertEquals("Registration failed. Please try again later.", response.getMessage());
    }

    @Test
    void givenValidToken_whenVerifyEmail_thenVerifyUserAndReturnTrue() {

        // Given
        when(userRepository.findByVerificationToken(verificationToken)).thenReturn(Optional.of(mockUser));

        // When
        boolean result = userService.verifyEmail(verificationToken);

        // Then
        assertTrue(result);
        assertTrue(mockUser.isEnabled());
        assertNull(mockUser.getVerificationToken());

        verify(userRepository).findByVerificationToken(verificationToken);
        verify(userRepository).save(mockUser);
    }

    @Test
    void givenAlreadyVerifiedUser_whenVerifyEmail_thenReturnTrueWithoutUpdating() {

        // Given
        User alreadyVerifiedUser = User.builder()
                .username("verifieduser")
                .email("verified@example.com")
                .verificationToken(verificationToken)
                .enabled(true)
                .build();

        when(userRepository.findByVerificationToken(verificationToken)).thenReturn(Optional.of(alreadyVerifiedUser));

        // When
        boolean result = userService.verifyEmail(verificationToken);

        // Then
        assertTrue(result);
        verify(userRepository).findByVerificationToken(verificationToken);
        // Verify that save was never called since user was already verified
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    void givenInvalidToken_whenVerifyEmail_thenThrowResourceNotFoundException() {

        // Given
        when(userRepository.findByVerificationToken(anyString())).thenReturn(Optional.empty());

        // When & Then
        assertThrows(ResourceNotFoundException.class, () -> userService.verifyEmail("invalid-token"));
        verify(userRepository).findByVerificationToken("invalid-token");
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    void givenNullToken_whenVerifyEmail_thenThrowResourceNotFoundException() {
        // When & Then
        assertThrows(ResourceNotFoundException.class, () -> userService.verifyEmail(null));
    }

    @Test
    void givenValidEmail_whenResendVerificationEmail_thenResendAndReturnTrue() {

        // Given
        User unverifiedUser = User.builder()
                .username("unverified")
                .email("unverified@example.com")
                .enabled(false)
                .verificationToken("old-token")
                .build();

        when(userRepository.findByEmail("unverified@example.com")).thenReturn(Optional.of(unverifiedUser));
        when(emailService.sendVerificationEmailAsync(any(User.class))).thenReturn(CompletableFuture.completedFuture(null));

        // When
        boolean result = userService.resendVerificationEmail("unverified@example.com");

        // Then
        assertTrue(result);
        verify(userRepository).findByEmail("unverified@example.com");
        verify(emailService).sendVerificationEmailAsync(unverifiedUser);
    }

    @Test
    void givenValidEmailWithNoToken_whenResendVerificationEmail_thenGenerateNewTokenAndResend() {

        // Given
        User unverifiedUserNoToken = User.builder()
                .username("unverified")
                .email("unverified@example.com")
                .enabled(false)
                .verificationToken(null)
                .build();

        when(userRepository.findByEmail("unverified@example.com")).thenReturn(Optional.of(unverifiedUserNoToken));
        when(userRepository.save(any(User.class))).thenReturn(unverifiedUserNoToken);
        when(emailService.sendVerificationEmailAsync(any(User.class))).thenReturn(CompletableFuture.completedFuture(null));

        // When
        boolean result = userService.resendVerificationEmail("unverified@example.com");

        // Then
        assertTrue(result);
        assertEquals(verificationToken, unverifiedUserNoToken.getVerificationToken());
        verify(userRepository).findByEmail("unverified@example.com");
        verify(emailService).generateVerificationToken();
        verify(userRepository).save(unverifiedUserNoToken);
        verify(emailService).sendVerificationEmailAsync(unverifiedUserNoToken);
    }

    @Test
    void givenNonExistentEmail_whenResendVerificationEmail_thenReturnFalse() {

        // Given
        String email = "nonexistent@example.com";
        when(userRepository.findByEmail(email)).thenReturn(Optional.empty());

        // When
        boolean result = userService.resendVerificationEmail(email);

        // Then
        assertFalse(result);
        verify(userRepository).findByEmail(email);
        verify(emailService, never()).sendVerificationEmailAsync(any(User.class));
    }

    @Test
    void givenAlreadyVerifiedUser_whenResendVerificationEmail_thenReturnFalse() {

        // Given
        User verifiedUser = User.builder()
                .username("verified")
                .email("verified@example.com")
                .enabled(true)
                .build();

        when(userRepository.findByEmail("verified@example.com")).thenReturn(Optional.of(verifiedUser));

        // When
        boolean result = userService.resendVerificationEmail("verified@example.com");

        // Then
        assertFalse(result);
        verify(userRepository).findByEmail("verified@example.com");
        verify(emailService, never()).sendVerificationEmailAsync(any(User.class));
    }

    @Test
    void givenNullEmail_whenResendVerificationEmail_thenReturnFalse() {

        // When
        boolean result = userService.resendVerificationEmail(null);

        // Then
        assertFalse(result);
        verify(userRepository, never()).findByEmail(anyString());
        verify(emailService, never()).sendVerificationEmailAsync(any(User.class));
    }

    @Test
    void givenValidToken_whenVerifyEmailAndGetResponse_thenReturnSuccessResponse() {

        // Given
        when(userRepository.findByVerificationToken(verificationToken)).thenReturn(Optional.of(mockUser));

        // When
        VerificationResponse response = userService.verifyEmailAndGetResponse(verificationToken);

        // Then
        assertNotNull(response);
        assertTrue(response.isSuccess());
        assertEquals("Your email has been verified successfully. You can now log in to your account.", response.getMessage());

        verify(userRepository).findByVerificationToken(verificationToken);
    }

    @Test
    void givenInvalidToken_whenVerifyEmailAndGetResponse_thenReturnFailureResponse() {

        // Given
        when(userRepository.findByVerificationToken("invalid-token")).thenReturn(Optional.empty());

        // When
        VerificationResponse response = userService.verifyEmailAndGetResponse("invalid-token");

        // Then
        assertNotNull(response);
        assertFalse(response.isSuccess());
        assertTrue(response.getMessage().contains("Verification failed"));

        // Allow multiple calls - use atLeast() since implementation might call it internally
        verify(userRepository, atLeast(1)).findByVerificationToken("invalid-token");
    }

    @Test
    void givenAlreadyVerifiedUser_whenVerifyEmailAndGetResponse_thenReturnAlreadyVerifiedResponse() {

        // Given
        User verifiedUser = User.builder()
                .username("verified")
                .email("verified@example.com")
                .enabled(true)
                .verificationToken(verificationToken)
                .build();

        // Mock the first lookup (verify operation will fail with ResourceNotFoundException)
        when(userRepository.findByVerificationToken(verificationToken))
                .thenThrow(new ResourceNotFoundException("Invalid verification token"))
                .thenReturn(Optional.of(verifiedUser)); // Return for subsequent calls

        // Mock the lookup by email
        when(userRepository.findByEmail(verifiedUser.getEmail())).thenReturn(Optional.of(verifiedUser));

        // When
        VerificationResponse response = userService.verifyEmailAndGetResponse(verificationToken);

        // Then
        assertNotNull(response);
        assertTrue(response.isSuccess());
        assertEquals("Your email was already verified. You can log in to your account.", response.getMessage());
    }

    @Test
    void givenNullToken_whenVerifyEmailAndGetResponse_thenReturnErrorResponse() {
        
        // When
        VerificationResponse response = userService.verifyEmailAndGetResponse(null);

        // Then
        assertNotNull(response);
        assertFalse(response.isSuccess());
        assertEquals("Verification failed. The token is empty or invalid.", response.getMessage());
    }
    
    // Admin functionality tests
    
    @Test
    void whenGetAllUsers_thenReturnAllUsers() {
        // Given
        when(userRepository.findAll()).thenReturn(Arrays.asList(regularUser, adminUser));
        
        // When
        List<UserResponse> result = userService.getAllUsers();
        
        // Then
        assertEquals(2, result.size());
        
        // Check first user (regular)
        UserResponse firstUser = result.get(0);
        assertEquals(regularUserId, firstUser.getId());
        assertEquals("user", firstUser.getUsername());
        assertEquals("USER", firstUser.getRole());
        
        // Check second user (admin)
        UserResponse secondUser = result.get(1);
        assertEquals("admin", secondUser.getUsername());
        assertEquals("ADMIN", secondUser.getRole());
        
        verify(userRepository).findAll();
    }
    
    @Test
    void givenValidRequest_whenSetUserRole_thenUpdateRoleAndReturnSuccess() {
        // Given
        when(userRepository.findById(regularUserId)).thenReturn(Optional.of(regularUser));
        
        // When
        GenericResponse response = userService.setUserRole(regularUserId, Role.ADMIN);
        
        // Then
        assertEquals(200, response.getStatus());
        assertEquals("User role updated successfully", response.getMessage());
        assertEquals(Role.ADMIN, regularUser.getRole());
        
        verify(userRepository).findById(regularUserId);
        verify(userRepository).save(regularUser);
    }
    
    @Test
    void givenNonExistentUser_whenSetUserRole_thenThrowException() {
        // Given
        UUID nonExistentId = UUID.randomUUID();
        when(userRepository.findById(nonExistentId)).thenReturn(Optional.empty());
        
        // When & Then
        assertThrows(ResourceNotFoundException.class, () -> 
            userService.setUserRole(nonExistentId, Role.ADMIN)
        );
        
        verify(userRepository).findById(nonExistentId);
        verify(userRepository, never()).save(any(User.class));
    }
} 