package dev.idachev.userservice.service;

import dev.idachev.userservice.config.EmailProperties;
import dev.idachev.userservice.exception.ResourceNotFoundException;
import dev.idachev.userservice.exception.VerificationException;
import dev.idachev.userservice.mapper.DtoMapper;
import dev.idachev.userservice.model.User;
import dev.idachev.userservice.repository.UserRepository;
import dev.idachev.userservice.security.UserPrincipal;
import dev.idachev.userservice.web.dto.AuthResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("VerificationService Tests")
@MockitoSettings(strictness = Strictness.LENIENT)
class VerificationServiceUTest {

    @Mock
    private UserRepository userRepository;
    @Mock
    private EmailService emailService;
    @Mock
    private TokenService tokenService;
    @Mock
    private EmailProperties emailProperties;

    @InjectMocks
    private VerificationService verificationService;

    private MockedStatic<DtoMapper> dtoMapperMockedStatic;

    @BeforeEach
    void setUp() {
        dtoMapperMockedStatic = Mockito.mockStatic(DtoMapper.class);
    }

    @AfterEach
    void tearDown() {
        dtoMapperMockedStatic.close();
    }

    @Test
    @DisplayName("generateVerificationToken should return a non-blank UUID string")
    void generateVerificationToken_shouldReturnUUIDString() {
        String token = verificationService.generateVerificationToken();
        assertThat(token).isNotBlank();
        // Basic check if it looks like a UUID
        assertThatCode(() -> UUID.fromString(token)).doesNotThrowAnyException();
    }

    @Test
    @DisplayName("buildVerificationUrl should construct URL correctly")
    void buildVerificationUrl_shouldConstructUrl() {
        // Given
        String token = "test-token";
        String baseUrl = "http://localhost:8080";
        String baseUrlWithSlash = "http://localhost:8080/";
        String expectedUrl = baseUrl + "/api/v1/verification/verify/" + token;

        when(emailProperties.getServiceBaseUrl()).thenReturn(baseUrl);
        assertThat(verificationService.buildVerificationUrl(token)).isEqualTo(expectedUrl);

        reset(emailProperties);
        when(emailProperties.getServiceBaseUrl()).thenReturn(baseUrlWithSlash);
        assertThat(verificationService.buildVerificationUrl(token)).isEqualTo(expectedUrl);
    }

    @Nested
    @DisplayName("getVerificationStatus Tests")
    class GetVerificationStatusTests {
        @Test
        @DisplayName("Should return AuthResponse with token if user is verified")
        void getVerificationStatus_whenUserVerified_shouldReturnAuthResponseWithToken() {
            // Given
            String email = "verified@test.com";
            // Ensure the mock user has a username, as UserPrincipal needs it
            User verifiedUser = User.builder()
                                .id(UUID.randomUUID())
                                .email(email)
                                .username("verifiedUser")
                                .enabled(true)
                                .build();
            String generatedToken = "jwt.token";
            AuthResponse expectedResponse = AuthResponse.builder().token(generatedToken).build(); // Simplified

            when(userRepository.findByEmail(email)).thenReturn(Optional.of(verifiedUser));
            when(tokenService.generateToken(any(UserPrincipal.class))).thenReturn(generatedToken);
            dtoMapperMockedStatic.when(() -> DtoMapper.mapToAuthResponse(verifiedUser, generatedToken)).thenReturn(expectedResponse);

            // When
            AuthResponse actualResponse = verificationService.getVerificationStatus(email);

            // Then
            assertThat(actualResponse).isEqualTo(expectedResponse);
            verify(userRepository).findByEmail(email);
            verify(tokenService).generateToken(argThat(p -> p.getUsername().equals(verifiedUser.getUsername())));
            dtoMapperMockedStatic.verify(() -> DtoMapper.mapToAuthResponse(verifiedUser, generatedToken));
        }

        @Test
        @DisplayName("Should return AuthResponse without token if user is not verified")
        void getVerificationStatus_whenUserNotVerified_shouldReturnAuthResponseWithoutToken() {
             // Given
            String email = "unverified@test.com";
            User unverifiedUser = User.builder().id(UUID.randomUUID()).email(email).enabled(false).build();
            AuthResponse expectedResponse = AuthResponse.builder().token("").build(); // Simplified

            when(userRepository.findByEmail(email)).thenReturn(Optional.of(unverifiedUser));
            // generateToken should not be called
            dtoMapperMockedStatic.when(() -> DtoMapper.mapToAuthResponse(unverifiedUser, "")).thenReturn(expectedResponse);

            // When
            AuthResponse actualResponse = verificationService.getVerificationStatus(email);

            // Then
             assertThat(actualResponse).isEqualTo(expectedResponse);
            verify(userRepository).findByEmail(email);
            verify(tokenService, never()).generateToken(any());
            dtoMapperMockedStatic.verify(() -> DtoMapper.mapToAuthResponse(unverifiedUser, ""));
        }

        @Test
        @DisplayName("Should throw ResourceNotFoundException if user email not found")
        void getVerificationStatus_whenUserNotFound_shouldThrowResourceNotFoundException() {
            // Given
            String email = "notfound@test.com";
            when(userRepository.findByEmail(email)).thenReturn(Optional.empty());

            // When & Then
            assertThatThrownBy(() -> verificationService.getVerificationStatus(email))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessageContaining(email);

            verify(userRepository).findByEmail(email);
             verifyNoInteractions(tokenService);
             dtoMapperMockedStatic.verify(() -> DtoMapper.mapToAuthResponse(any(), any()), never());
        }
    }

    @Nested
    @DisplayName("verifyEmail Tests")
    class VerifyEmailTests {
        @Test
        @DisplayName("Should enable user and clear token when token is valid and user not enabled")
        void verifyEmail_withValidTokenAndUserNotEnabled_shouldEnableUser() {
            // Given
            String token = "valid-token";
            User user = User.builder()
                        .id(UUID.randomUUID())
                        .username("toVerify")
                        .enabled(false)
                        .verificationToken(token)
                        .build();

            when(userRepository.findByVerificationToken(token)).thenReturn(Optional.of(user));
            when(userRepository.save(any(User.class))).thenAnswer(inv -> inv.getArgument(0));

            // When
            verificationService.verifyEmail(token);

            // Then
            verify(userRepository).findByVerificationToken(token);
            ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
            verify(userRepository).save(userCaptor.capture());

            User savedUser = userCaptor.getValue();
            assertThat(savedUser.isEnabled()).isTrue();
            assertThat(savedUser.getVerificationToken()).isNull(); // Token should be cleared
        }

        @Test
        @DisplayName("Should throw VerificationException for blank token")
        void verifyEmail_withBlankToken_shouldThrowVerificationException() {
            assertThatThrownBy(() -> verificationService.verifyEmail(null))
                .isInstanceOf(VerificationException.class)
                .hasMessageContaining("blank");
            assertThatThrownBy(() -> verificationService.verifyEmail("  "))
                .isInstanceOf(VerificationException.class)
                .hasMessageContaining("blank");
            verifyNoInteractions(userRepository);
        }

        @Test
        @DisplayName("Should throw ResourceNotFoundException for invalid token")
        void verifyEmail_withInvalidToken_shouldThrowResourceNotFoundException() {
            // Given
            String token = "invalid-token";
            when(userRepository.findByVerificationToken(token)).thenReturn(Optional.empty());

            // When & Then
            assertThatThrownBy(() -> verificationService.verifyEmail(token))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessageContaining("Invalid or expired");

            verify(userRepository).findByVerificationToken(token);
            verify(userRepository, never()).save(any());
        }

        @Test
        @DisplayName("Should throw VerificationException if user already enabled")
        void verifyEmail_whenUserAlreadyEnabled_shouldThrowVerificationException() {
            // Given
            String token = "already-verified-token";
             User user = User.builder()
                        .id(UUID.randomUUID())
                        .enabled(true) // Already enabled
                        .verificationToken(token)
                        .build();
            when(userRepository.findByVerificationToken(token)).thenReturn(Optional.of(user));

            // When & Then
             assertThatThrownBy(() -> verificationService.verifyEmail(token))
                .isInstanceOf(VerificationException.class)
                .hasMessageContaining("already verified");

            verify(userRepository).findByVerificationToken(token);
            verify(userRepository, never()).save(any());
        }
    }

    @Nested
    @DisplayName("resendVerificationEmail Tests")
    class ResendVerificationEmailTests {
        @Test
        @DisplayName("Should resend email with existing token if user not verified")
        void resendVerificationEmail_whenUserNotVerifiedWithToken_shouldResendEmail() {
            // Given
            String email = "resend@test.com";
            String existingToken = "existing-token";
            User user = User.builder()
                        .id(UUID.randomUUID())
                        .email(email)
                        .enabled(false)
                        .verificationToken(existingToken)
                        .build();
            String verificationUrl = "http://base.url/api/v1/verification/verify/" + existingToken;

            when(userRepository.findByEmail(email)).thenReturn(Optional.of(user));
            when(emailProperties.getServiceBaseUrl()).thenReturn("http://base.url");
            doNothing().when(emailService).sendVerificationEmail(user, verificationUrl);

            // When
            verificationService.resendVerificationEmail(email);

            // Then
            verify(userRepository).findByEmail(email);
            verify(userRepository, never()).save(any()); // No new token generated
            verify(emailProperties).getServiceBaseUrl();
            verify(emailService).sendVerificationEmail(user, verificationUrl);
        }

        @Test
        @DisplayName("Should generate new token, save user, and resend email if user has no token")
        void resendVerificationEmail_whenUserNotVerifiedWithoutToken_shouldGenerateSaveAndResend() {
            // Given
            String email = "resend-notoken@test.com";
            User user = User.builder()
                        .id(UUID.randomUUID())
                        .email(email)
                        .enabled(false)
                        .verificationToken(null) // No token initially
                        .build();
            String generatedToken = "newly-generated-token"; // Assume generate returns this
            String verificationUrl = "http://base.url/api/v1/verification/verify/" + generatedToken;

            // Mock findByEmail
            when(userRepository.findByEmail(email)).thenReturn(Optional.of(user));
            // Mock save to capture updated user
            ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
            when(userRepository.save(userCaptor.capture())).thenAnswer(inv -> inv.getArgument(0));
            // Mock URL building
            when(emailProperties.getServiceBaseUrl()).thenReturn("http://base.url");
            // Mock email sending (verify arguments later)
            ArgumentCaptor<String> urlCaptor = ArgumentCaptor.forClass(String.class);
            doNothing().when(emailService).sendVerificationEmail(any(User.class), urlCaptor.capture()); // Capture URL

            // When
            // We can't easily mock the internal call to generateVerificationToken without spying.
            // Instead, we verify that save is called with a user that HAS a token,
            // and that sendEmail is called with the corresponding URL.
            verificationService.resendVerificationEmail(email);

            // Then
            verify(userRepository).findByEmail(email);
            verify(userRepository).save(any(User.class)); // Save should be called
            User savedUser = userCaptor.getValue();
            assertThat(savedUser.getVerificationToken()).isNotNull().isNotBlank(); // Verify token was set
            // Use the captured token to verify subsequent calls
            String capturedToken = savedUser.getVerificationToken();
            String expectedUrl = "http://base.url/api/v1/verification/verify/" + capturedToken;
            verify(emailProperties).getServiceBaseUrl(); // Ensure base URL was fetched
            verify(emailService).sendVerificationEmail(eq(savedUser), eq(expectedUrl)); // Verify with captured user and exact expected URL
            assertThat(urlCaptor.getValue()).isEqualTo(expectedUrl); // Double check captured URL
        }

        @Test
        @DisplayName("Should throw VerificationException if user already verified")
        void resendVerificationEmail_whenUserAlreadyVerified_shouldThrowVerificationException() {
             // Given
            String email = "already-verified@test.com";
            User user = User.builder().email(email).enabled(true).build();
            when(userRepository.findByEmail(email)).thenReturn(Optional.of(user));

            // When & Then
             assertThatThrownBy(() -> verificationService.resendVerificationEmail(email))
                .isInstanceOf(VerificationException.class)
                .hasMessageContaining("already verified");

             verify(userRepository).findByEmail(email);
             verifyNoInteractions(emailService, tokenService, emailProperties);
             verify(userRepository, never()).save(any());
        }

        @Test
        @DisplayName("Should throw ResourceNotFoundException if email not found")
        void resendVerificationEmail_whenEmailNotFound_shouldThrowResourceNotFoundException() {
             // Given
            String email = "notfound@test.com";
            when(userRepository.findByEmail(email)).thenReturn(Optional.empty());

             // When & Then
            assertThatThrownBy(() -> verificationService.resendVerificationEmail(email))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessageContaining(email);

            verify(userRepository).findByEmail(email);
            verifyNoInteractions(emailService, tokenService, emailProperties);
        }
    }
} 