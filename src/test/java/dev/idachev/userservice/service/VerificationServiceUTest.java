package dev.idachev.userservice.service;

import dev.idachev.userservice.exception.ResourceNotFoundException;
import dev.idachev.userservice.exception.VerificationException;
import dev.idachev.userservice.model.Role;
import dev.idachev.userservice.model.User;
import dev.idachev.userservice.repository.UserRepository;
import dev.idachev.userservice.security.UserPrincipal;
import dev.idachev.userservice.web.dto.AuthResponse;
import dev.idachev.userservice.web.dto.GenericResponse;
import dev.idachev.userservice.web.dto.VerificationResponse;
import dev.idachev.userservice.web.dto.VerificationResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.web.servlet.view.RedirectView;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class VerificationServiceUTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private EmailService emailService;

    @Mock
    private TokenService tokenService;

    @Captor
    private ArgumentCaptor<User> userCaptor;

    private VerificationService verificationService;

    private User testUser;
    private String verificationToken;

    @BeforeEach
    void setUp() {
        verificationService = new VerificationService(userRepository, emailService, tokenService);

        verificationToken = UUID.randomUUID().toString();
        testUser = User.builder()
                .id(UUID.randomUUID())
                .username("testuser")
                .email("test@example.com")
                .password("encodedPassword")
                .role(Role.USER)
                .enabled(false)
                .verificationToken(verificationToken)
                .createdOn(LocalDateTime.now())
                .build();
    }

    @Test
    @DisplayName("Should return verification status for unverified user")
    void should_ReturnVerificationStatus_ForUnverifiedUser() {
        // Given
        when(userRepository.findByEmail(testUser.getEmail())).thenReturn(Optional.of(testUser));
        
        // When
        AuthResponse response = verificationService.getVerificationStatus(testUser.getEmail());
        
        // Then
        assertThat(response).isNotNull();
        assertThat(response.getToken()).isEmpty();
        assertThat(response.getUser().isVerified()).isFalse();
        verify(tokenService, never()).generateToken(any(UserPrincipal.class));
    }

    @Test
    @DisplayName("Should return verification status with token for verified user")
    void should_ReturnVerificationStatusWithToken_ForVerifiedUser() {
        // Given
        testUser.setEnabled(true);
        String authToken = "valid.jwt.token";
        
        when(userRepository.findByEmail(testUser.getEmail())).thenReturn(Optional.of(testUser));
        when(tokenService.generateToken(any(UserPrincipal.class))).thenReturn(authToken);
        
        // When
        AuthResponse response = verificationService.getVerificationStatus(testUser.getEmail());
        
        // Then
        assertThat(response).isNotNull();
        assertThat(response.getToken()).isEqualTo(authToken);
        assertThat(response.getUser().isVerified()).isTrue();
        verify(tokenService).generateToken(any(UserPrincipal.class));
    }

    @Test
    @DisplayName("Should throw ResourceNotFoundException when user email doesn't exist")
    void should_ThrowResourceNotFoundException_WhenUserEmailDoesntExist() {
        // Given
        String nonExistentEmail = "nonexistent@example.com";
        when(userRepository.findByEmail(nonExistentEmail)).thenReturn(Optional.empty());
        
        // When/Then
        assertThatThrownBy(() -> verificationService.getVerificationStatus(nonExistentEmail))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessageContaining("User not found");
    }

    @Test
    @DisplayName("Should verify email successfully when valid token is provided")
    void should_VerifyEmail_WhenValidTokenIsProvided() {
        // Given
        when(userRepository.findByVerificationToken(verificationToken)).thenReturn(Optional.of(testUser));
        
        // When
        boolean result = verificationService.verifyEmail(verificationToken);
        
        // Then
        verify(userRepository).save(userCaptor.capture());
        User savedUser = userCaptor.getValue();
        
        assertThat(result).isTrue();
        assertThat(savedUser.isEnabled()).isTrue();
        assertThat(savedUser.getVerificationToken()).isNull();
        assertThat(savedUser.getUpdatedOn()).isNotNull();
    }

    @Test
    @DisplayName("Should throw VerificationException when token is empty")
    void should_ThrowVerificationException_WhenTokenIsEmpty() {
        // When/Then
        assertThatThrownBy(() -> verificationService.verifyEmail(""))
                .isInstanceOf(VerificationException.class)
                .hasMessageContaining("cannot be empty");
    }

    @Test
    @DisplayName("Should throw VerificationException when token is invalid")
    void should_ThrowVerificationException_WhenTokenIsInvalid() {
        // Given
        String invalidToken = "invalid-token";
        when(userRepository.findByVerificationToken(invalidToken)).thenReturn(Optional.empty());
        
        // When/Then
        assertThatThrownBy(() -> verificationService.verifyEmail(invalidToken))
                .isInstanceOf(VerificationException.class)
                .hasMessageContaining("Invalid verification token");
    }

    @Test
    @DisplayName("Should return success for already verified user")
    void should_ReturnSuccess_ForAlreadyVerifiedUser() {
        // Given
        testUser.setEnabled(true);
        when(userRepository.findByVerificationToken(verificationToken)).thenReturn(Optional.of(testUser));
        
        // When
        boolean result = verificationService.verifyEmail(verificationToken);
        
        // Then
        assertThat(result).isTrue();
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    @DisplayName("Should resend verification email successfully")
    void should_ResendVerificationEmail_Successfully() {
        // Given
        when(userRepository.findByEmail(testUser.getEmail())).thenReturn(Optional.of(testUser));
        lenient().when(userRepository.save(any(User.class))).thenReturn(testUser);
        
        // When
        GenericResponse response = verificationService.resendVerificationEmail(testUser.getEmail());
        
        // Then
        verify(emailService).sendVerificationEmailAsync(testUser);
        assertThat(response.isSuccess()).isTrue();
        assertThat(response.getMessage()).contains("resent");
    }

    @Test
    @DisplayName("Should not resend verification email for verified users")
    void should_NotResendVerificationEmail_ForVerifiedUsers() {
        // Given
        testUser.setEnabled(true);
        when(userRepository.findByEmail(testUser.getEmail())).thenReturn(Optional.of(testUser));
        
        // When
        GenericResponse response = verificationService.resendVerificationEmail(testUser.getEmail());
        
        // Then
        verify(emailService, never()).sendVerificationEmailAsync(any(User.class));
        assertThat(response.isSuccess()).isFalse();
        assertThat(response.getMessage()).contains("already verified");
    }

    @Test
    @DisplayName("Should generate new verification token if none exists")
    void should_GenerateNewVerificationToken_IfNoneExists() {
        // Given
        testUser.setVerificationToken(null);
        String newToken = "new-verification-token";
        
        when(userRepository.findByEmail(testUser.getEmail())).thenReturn(Optional.of(testUser));
        when(emailService.generateVerificationToken()).thenReturn(newToken);
        when(userRepository.save(any(User.class))).thenReturn(testUser);
        
        // When
        verificationService.resendVerificationEmail(testUser.getEmail());
        
        // Then
        verify(userRepository).save(userCaptor.capture());
        User savedUser = userCaptor.getValue();
        
        assertThat(savedUser.getVerificationToken()).isEqualTo(newToken);
    }
} 