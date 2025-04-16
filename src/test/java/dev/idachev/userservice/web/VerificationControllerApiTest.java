package dev.idachev.userservice.web;

import dev.idachev.userservice.service.VerificationService;
import dev.idachev.userservice.web.dto.AuthResponse;
import dev.idachev.userservice.web.dto.GenericResponse;
import dev.idachev.userservice.web.dto.UserResponse;
import dev.idachev.userservice.web.dto.VerificationResponse;
import dev.idachev.userservice.web.dto.VerificationResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.servlet.view.RedirectView;

import java.time.LocalDateTime;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class VerificationControllerApiTest {

    @Mock
    private VerificationService verificationService;

    @InjectMocks
    private VerificationController verificationController;

    private String validEmail;
    private String verificationToken;
    private AuthResponse authResponse;
    private VerificationResult successResult;
    private VerificationResult failureResult;
    private VerificationResponse verificationResponse;
    private GenericResponse genericResponse;

    @BeforeEach
    void setUp() {
        validEmail = "test@example.com";
        verificationToken = UUID.randomUUID().toString();
        
        // Set frontend URL through reflection
        ReflectionTestUtils.setField(verificationController, "frontendUrl", "http://localhost:3000");
        ReflectionTestUtils.setField(verificationController, "signinRoute", "/signin");
        
        // Create test responses
        UserResponse userResponse = UserResponse.builder()
                .id(UUID.randomUUID())
                .username("testuser")
                .email(validEmail)
                .role("USER")
                .verified(true)
                .createdOn(LocalDateTime.now())
                .build();
                
        authResponse = AuthResponse.builder()
                .token("valid.jwt.token")
                .user(userResponse)
                .build();
                
        successResult = VerificationResult.success();
        failureResult = VerificationResult.failure("InvalidToken");
        
        verificationResponse = VerificationResponse.builder()
                .success(true)
                .message("Email verified successfully")
                .timestamp(LocalDateTime.now())
                .build();
        
        genericResponse = GenericResponse.builder()
                .success(true)
                .message("Verification email has been sent")
                .status(HttpStatus.OK.value())
                .build();
    }

    @Test
    @DisplayName("Should return verification status when valid email is provided")
    void should_ReturnVerificationStatus_When_ValidEmailIsProvided() {
        // Given
        when(verificationService.getVerificationStatus(validEmail)).thenReturn(authResponse);
        
        // When
        ResponseEntity<AuthResponse> response = verificationController.getVerificationStatus(validEmail);
        
        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isEqualTo(authResponse);
        verify(verificationService).getVerificationStatus(validEmail);
    }
    
    @Test
    @DisplayName("Should resend verification email when valid email is provided")
    void should_ResendVerificationEmail_When_ValidEmailIsProvided() {
        // Given
        when(verificationService.resendVerificationEmail(validEmail)).thenReturn(genericResponse);
        
        // When
        ResponseEntity<GenericResponse> response = verificationController.resendVerificationEmail(validEmail);
        
        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isEqualTo(genericResponse);
        assertThat(response.getBody().isSuccess()).isTrue();
        assertThat(response.getBody().getMessage()).contains("email has been sent");
        verify(verificationService).resendVerificationEmail(validEmail);
    }
    
    @Test
    @DisplayName("Should redirect to sign-in page with success when verification is successful")
    void should_RedirectToSignInPage_With_Success_When_VerificationIsSuccessful() {
        // Given
        when(verificationService.verifyEmailForRedirect(verificationToken)).thenReturn(successResult);
        
        // When
        RedirectView redirectView = verificationController.verifyEmail(verificationToken);
        
        // Then
        assertThat(redirectView.getUrl()).isEqualTo("http://localhost:3000/signin?verified=true");
        verify(verificationService).verifyEmailForRedirect(verificationToken);
    }
    
    @Test
    @DisplayName("Should redirect to sign-in page with error when verification fails")
    void should_RedirectToSignInPage_With_Error_When_VerificationFails() {
        // Given
        when(verificationService.verifyEmailForRedirect(verificationToken)).thenReturn(failureResult);
        
        // When
        RedirectView redirectView = verificationController.verifyEmail(verificationToken);
        
        // Then
        assertThat(redirectView.getUrl()).isEqualTo("http://localhost:3000/signin?verified=false&error=InvalidToken");
        verify(verificationService).verifyEmailForRedirect(verificationToken);
    }
    
    @Test
    @DisplayName("Should verify email via API when token is provided")
    void should_VerifyEmailViaApi_When_TokenIsProvided() {
        // Given
        when(verificationService.verifyEmailAndGetResponse(verificationToken)).thenReturn(verificationResponse);
        
        // When
        ResponseEntity<VerificationResponse> response = verificationController.verifyEmailApi(verificationToken);
        
        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isEqualTo(verificationResponse);
        assertThat(response.getBody().isSuccess()).isTrue();
        assertThat(response.getBody().getMessage()).contains("verified successfully");
        verify(verificationService).verifyEmailAndGetResponse(verificationToken);
    }
} 