package dev.idachev.userservice.service;

import dev.idachev.userservice.config.EmailProperties;
import dev.idachev.userservice.exception.AccountVerificationException;
import dev.idachev.userservice.exception.AuthenticationException;
import dev.idachev.userservice.exception.DuplicateUserException;
import dev.idachev.userservice.exception.UserNotFoundException;
import dev.idachev.userservice.mapper.DtoMapper;
import dev.idachev.userservice.model.Role;
import dev.idachev.userservice.model.User;
import dev.idachev.userservice.repository.UserRepository;
import dev.idachev.userservice.security.UserPrincipal;
import dev.idachev.userservice.web.dto.AuthResponse;
import dev.idachev.userservice.web.dto.SignInRequest;
import dev.idachev.userservice.web.dto.UserResponse;
import dev.idachev.userservice.web.dto.RegisterRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.mockito.Mockito.lenient;

@ExtendWith(MockitoExtension.class)
@DisplayName("AuthenticationService Tests")
@MockitoSettings(strictness = Strictness.LENIENT)
class AuthenticationServiceUTest {

    @Mock
    private UserRepository userRepository;
    @Mock
    private AuthenticationManager authenticationManager;
    @Mock
    private TokenService tokenService;
    @Mock
    private PasswordEncoder passwordEncoder; // Mocked, potentially used in findUserByIdentifier logic indirectly
    @Mock
    private EmailService emailService; // Mocked, not used in signIn
    @Mock
    private UserService userService; // Mocked, not used in signIn
    @Mock
    private VerificationService verificationService; // Mocked, not used in signIn
    @Mock
    private UserDetailsService userDetailsService; // Mocked, used for manual checks if implemented

    @InjectMocks
    private AuthenticationService authenticationService;

    private MockedStatic<DtoMapper> dtoMapperMockedStatic;

    @BeforeEach
    void setUp() {
        dtoMapperMockedStatic = Mockito.mockStatic(DtoMapper.class);
    }

    @AfterEach
    void tearDown() {
        dtoMapperMockedStatic.close();
    }

    @Nested
    @DisplayName("signIn Tests")
    class SignInTests {

        private SignInRequest signInRequest;
        private User testUser;
        private UserPrincipal testUserPrincipal;
        private Authentication successfulAuthentication;

        @BeforeEach
        void setupTestData() {
            String username = "testuser";
            String password = "password123";
            signInRequest = new SignInRequest(username, password);

            testUser = User.builder()
                    .id(UUID.randomUUID())
                    .username(username)
                    .email("test@test.com")
                    .password("encodedPassword") // Assume encoded
                    .role(Role.USER)
                    .enabled(true) // Default: enabled
                    .banned(false) // Default: not banned
                    .build();

            testUserPrincipal = new UserPrincipal(testUser);
            successfulAuthentication = mock(Authentication.class); // Mock Authentication object
            when(successfulAuthentication.getPrincipal()).thenReturn(testUserPrincipal);

            // Make the AuthenticationManager mock lenient as it's not used in all signIn tests
            lenient().when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                     .thenReturn(successfulAuthentication);
            // Other mocks in setup might also need lenient() if they cause issues
        }

        @Test
        @DisplayName("Should sign in successfully and return AuthResponse with token")
        void signIn_whenCredentialsValidAndUserActive_shouldReturnAuthResponse() {
            // Given
            String generatedToken = "jwt.token.string";
            // Create the nested UserResponse that AuthResponse expects
            UserResponse embeddedUserResponse = UserResponse.builder()
                                                  .id(testUser.getId())
                                                  .username(testUser.getUsername())
                                                  .email(testUser.getEmail())
                                                  .role(testUser.getRole().name())
                                                  .enabled(testUser.isEnabled())
                                                  .banned(testUser.isBanned())
                                                  .build();

            // Build AuthResponse embedding UserResponse
            AuthResponse expectedResponse = AuthResponse.builder()
                                                .token(generatedToken)
                                                .user(embeddedUserResponse)
                                                .username(testUser.getUsername())
                                                .email(testUser.getEmail())
                                                .role(testUser.getRole().name())
                                                .enabled(testUser.isEnabled())
                                                .banned(testUser.isBanned())
                                                .success(true)
                                                .message("Authentication successful") // Assuming this message
                                                .build();

            // Mock finding user by identifier (username)
            when(userRepository.findByUsername(signInRequest.identifier())).thenReturn(Optional.of(testUser));
            when(userRepository.findByEmail(signInRequest.identifier())).thenReturn(Optional.empty()); // Assume not found by email

            // Mock repository save for last login update
            when(userRepository.save(any(User.class))).thenAnswer(inv -> inv.getArgument(0));

            // Mock token generation
            when(tokenService.generateToken(testUserPrincipal)).thenReturn(generatedToken);

            // Mock DTO mapping to return the fully built AuthResponse
            dtoMapperMockedStatic.when(() -> DtoMapper.mapToAuthResponse(any(User.class), eq(generatedToken))).thenReturn(expectedResponse);

            // When
            AuthResponse actualResponse = authenticationService.signIn(signInRequest);

            // Then
            assertThat(actualResponse).isNotNull();
            assertThat(actualResponse.getToken()).isEqualTo(generatedToken);
            // Assert properties of the embedded UserResponse
            assertThat(actualResponse.getUser()).isNotNull();
            assertThat(actualResponse.getUser().getId()).isEqualTo(testUser.getId());
            assertThat(actualResponse.getUsername()).isEqualTo(testUser.getUsername()); // Also check top-level username

            // Verify user was found
            verify(userRepository, times(1)).findByUsername(signInRequest.identifier());
            // Verify authentication manager was called with correct credentials
            verify(authenticationManager).authenticate(argThat(token ->
                    token.getName().equals(testUser.getUsername()) &&
                    token.getCredentials().equals(signInRequest.password())
            ));
            // Verify user last login updated and saved
            verify(userRepository).save(argThat(user ->
                    user.getId().equals(testUser.getId()) &&
                    user.getLastLogin() != null && // Check that lastLogin was updated
                    user.isLoggedIn() // Check that loggedIn flag is set
            ));
            // Verify token was generated
            verify(tokenService).generateToken(testUserPrincipal);
            // Verify DTO mapping
            dtoMapperMockedStatic.verify(() -> DtoMapper.mapToAuthResponse(any(User.class), eq(generatedToken)), times(1));
        }

        @Test
        @DisplayName("Should throw AuthenticationException when credentials are invalid")
        void signIn_whenCredentialsInvalid_shouldThrowAuthenticationException() {
            // Given
            // Mock finding user by identifier (username)
            when(userRepository.findByUsername(signInRequest.identifier())).thenReturn(Optional.of(testUser));
            when(userRepository.findByEmail(signInRequest.identifier())).thenReturn(Optional.empty()); // Assume not found by email

            // Mock authenticationManager throwing BadCredentialsException
            when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                    .thenThrow(new BadCredentialsException("Bad credentials"));

            // When & Then
            assertThatThrownBy(() -> authenticationService.signIn(signInRequest))
                    .isInstanceOf(AuthenticationException.class)
                    .hasMessageContaining("Invalid credentials");

            // Verify user was found
            verify(userRepository, times(1)).findByUsername(signInRequest.identifier());
            // Verify authentication manager was called
            verify(authenticationManager).authenticate(any(UsernamePasswordAuthenticationToken.class));
            // Verify save and token generation NOT called
            verify(userRepository, never()).save(any(User.class));
            verify(tokenService, never()).generateToken(any(UserPrincipal.class));
        }

        @Test
        @DisplayName("Should throw AuthenticationException when user not found by identifier")
        void signIn_whenUserNotFound_shouldThrowAuthenticationException() {
            // Given
            // Mock finding user returns empty Optional for both username and email
            when(userRepository.findByUsername(signInRequest.identifier())).thenReturn(Optional.empty());
            when(userRepository.findByEmail(signInRequest.identifier())).thenReturn(Optional.empty());

            // When & Then
            assertThatThrownBy(() -> authenticationService.signIn(signInRequest))
                    .isInstanceOf(AuthenticationException.class)
                    .hasMessageContaining("Invalid credentials"); // Method throws this for not found too

            // Verify user was searched
            verify(userRepository, times(1)).findByUsername(signInRequest.identifier());
            verify(userRepository, times(1)).findByEmail(signInRequest.identifier());
            // Verify no other interactions
            verify(authenticationManager, never()).authenticate(any());
            verify(userRepository, never()).save(any(User.class));
            verify(tokenService, never()).generateToken(any(UserPrincipal.class));
        }

        @Test
        @DisplayName("Should throw AccountVerificationException when user is not enabled")
        void signIn_whenUserNotEnabled_shouldThrowAccountVerificationException() {
            // Given
            testUser = testUser.toBuilder().enabled(false).build(); // User is not enabled
            when(userRepository.findByUsername(signInRequest.identifier())).thenReturn(Optional.of(testUser));
            when(userRepository.findByEmail(signInRequest.identifier())).thenReturn(Optional.empty());

            // When & Then
            assertThatThrownBy(() -> authenticationService.signIn(signInRequest))
                    .isInstanceOf(AccountVerificationException.class)
                    .hasMessageContaining("Account not verified. Please check your email.");

            // Verify user was found
            verify(userRepository, times(1)).findByUsername(signInRequest.identifier());
            // Verify authentication manager NOT called
            verify(authenticationManager, never()).authenticate(any());
        }

        @Test
        @DisplayName("Should throw AuthenticationException when user is banned")
        void signIn_whenUserIsBanned_shouldThrowAuthenticationException() {
            // Given
            testUser = testUser.toBuilder().banned(true).build(); // User is banned
            when(userRepository.findByUsername(signInRequest.identifier())).thenReturn(Optional.of(testUser));
            when(userRepository.findByEmail(signInRequest.identifier())).thenReturn(Optional.empty());

            // When & Then
            assertThatThrownBy(() -> authenticationService.signIn(signInRequest))
                    .isInstanceOf(AuthenticationException.class)
                    .hasMessageContaining("Your account has been banned.");

            // Verify user was found
            verify(userRepository, times(1)).findByUsername(signInRequest.identifier());
            // Verify authentication manager NOT called
            verify(authenticationManager, never()).authenticate(any());
        }

         @Test
        @DisplayName("Should sign in successfully when identifier is email")
        void signIn_whenIdentifierIsEmailAndCredentialsValid_shouldReturnAuthResponse() {
            // Given
            String email = "test@test.com";
            String password = "password123";
            SignInRequest emailSignInRequest = new SignInRequest(email, password);
            testUser = testUser.toBuilder().email(email).username("userForEmail").build(); // Ensure user matches email
            testUserPrincipal = new UserPrincipal(testUser);

            String generatedToken = "jwt.token.string.email";
             // Create the nested UserResponse
            UserResponse embeddedUserResponse = UserResponse.builder()
                                                  .id(testUser.getId())
                                                  .username(testUser.getUsername())
                                                  // ... other fields ...
                                                  .build();
             // Build AuthResponse embedding UserResponse
            AuthResponse expectedResponse = AuthResponse.builder()
                                                .token(generatedToken)
                                                .user(embeddedUserResponse)
                                                .username(testUser.getUsername())
                                                // ... other fields ...
                                                .build();

            // Mock finding user by identifier (username fails, email succeeds)
            when(userRepository.findByUsername(emailSignInRequest.identifier())).thenReturn(Optional.empty());
            when(userRepository.findByEmail(emailSignInRequest.identifier())).thenReturn(Optional.of(testUser));

            // Mock successful authenticationManager call (using the actual username found)
            successfulAuthentication = mock(Authentication.class);
            when(successfulAuthentication.getPrincipal()).thenReturn(testUserPrincipal);
            when(authenticationManager.authenticate(
                    argThat(token -> token.getName().equals(testUser.getUsername()) && token.getCredentials().equals(password))))
                    .thenReturn(successfulAuthentication);

            when(userRepository.save(any(User.class))).thenAnswer(inv -> inv.getArgument(0));
            when(tokenService.generateToken(testUserPrincipal)).thenReturn(generatedToken);
            dtoMapperMockedStatic.when(() -> DtoMapper.mapToAuthResponse(any(User.class), eq(generatedToken))).thenReturn(expectedResponse);

            // When
            AuthResponse actualResponse = authenticationService.signIn(emailSignInRequest);

            // Then
            assertThat(actualResponse).isNotNull();
            assertThat(actualResponse.getToken()).isEqualTo(generatedToken);
            assertThat(actualResponse.getUser()).isNotNull();
            assertThat(actualResponse.getUser().getId()).isEqualTo(testUser.getId()); // Check ID within embedded user

            // Verify user was found by email
            verify(userRepository, times(1)).findByUsername(emailSignInRequest.identifier());
            verify(userRepository, times(1)).findByEmail(emailSignInRequest.identifier());
            // Verify authentication manager was called with correct username/password
             verify(authenticationManager).authenticate(argThat(token ->
                    token.getName().equals(testUser.getUsername()) &&
                    token.getCredentials().equals(password)
            ));
            verify(userRepository).save(any(User.class));
            verify(tokenService).generateToken(testUserPrincipal);
            dtoMapperMockedStatic.verify(() -> DtoMapper.mapToAuthResponse(any(User.class), eq(generatedToken)), times(1));
        }
    }

    @Nested
    @DisplayName("register Tests")
    class RegisterTests {

        private RegisterRequest registerRequest;
        private User registeredUser;
        private String verificationToken;

        @BeforeEach
        void setupRegisterData() {
            registerRequest = new RegisterRequest("newreg", "newreg@test.com", "PasswordReg123!");
            verificationToken = "verify-me-token";
            registeredUser = User.builder()
                                .id(UUID.randomUUID())
                                .username(registerRequest.username())
                                .email(registerRequest.email())
                                .password("encodedPasswordReg")
                                .role(Role.USER)
                                .enabled(false)
                                .verificationToken(verificationToken) // Ensure token is set
                                .build();
        }

        @Test
        @DisplayName("Should register successfully, send email, and return AuthResponse")
        void register_whenUsernameAndEmailAvailable_shouldRegisterAndSendEmail() {
            // Given
            String verificationUrl = "http://localhost/verify?token=" + verificationToken;
            String jwtToken = "jwt.register.token";
            UserResponse embeddedUserResponse = UserResponse.builder().id(registeredUser.getId()).username(registeredUser.getUsername()).build(); // Simplified
            AuthResponse expectedResponse = AuthResponse.builder().token(jwtToken).user(embeddedUserResponse).username(registeredUser.getUsername()).build(); // Simplified

            // Mock checks: username and email do NOT exist
            when(userRepository.existsByUsername(registerRequest.username())).thenReturn(false);
            when(userRepository.existsByEmail(registerRequest.email())).thenReturn(false);

            // Mock the call to userService.registerUser (returns the user with the token)
            when(userService.registerUser(registerRequest)).thenReturn(registeredUser);

            // Mock verification service URL building
            when(verificationService.buildVerificationUrl(verificationToken)).thenReturn(verificationUrl);

            // Mock email sending (assume success)
            doNothing().when(emailService).sendVerificationEmail(registeredUser, verificationUrl);

            // Mock token generation
            when(tokenService.generateToken(any(UserPrincipal.class))).thenReturn(jwtToken);

            // Mock DTO mapping
             dtoMapperMockedStatic.when(() -> DtoMapper.mapToAuthResponse(eq(registeredUser), eq(jwtToken))).thenReturn(expectedResponse);

            // When
            AuthResponse actualResponse = authenticationService.register(registerRequest);

            // Then
            assertThat(actualResponse).isNotNull();
            assertThat(actualResponse.getToken()).isEqualTo(jwtToken);
            assertThat(actualResponse.getUsername()).isEqualTo(registerRequest.username());

            // Verify interactions
            verify(userRepository).existsByUsername(registerRequest.username());
            verify(userRepository).existsByEmail(registerRequest.email());
            verify(userService).registerUser(registerRequest);
            verify(verificationService).buildVerificationUrl(verificationToken);
            verify(emailService).sendVerificationEmail(registeredUser, verificationUrl);
            // Verify UserPrincipal has the registered user details when generating token
             verify(tokenService).generateToken(argThat(principal -> {
                UserPrincipal userPrincipal = (UserPrincipal) principal; // Cast to UserPrincipal
                return userPrincipal.getUsername().equals(registeredUser.getUsername()) &&
                       userPrincipal.user().getId().equals(registeredUser.getId()); // Use record accessor user()
            }
            ));
            dtoMapperMockedStatic.verify(() -> DtoMapper.mapToAuthResponse(registeredUser, jwtToken));
        }

        @Test
        @DisplayName("Should throw DuplicateUserException when username already exists")
        void register_whenUsernameExists_shouldThrowDuplicateUserException() {
            // Given
            when(userRepository.existsByUsername(registerRequest.username())).thenReturn(true);
            // No need to mock email check if username check comes first

            // When & Then
            assertThatThrownBy(() -> authenticationService.register(registerRequest))
                .isInstanceOf(DuplicateUserException.class)
                .hasMessageContaining("Username already exists");

            // Verify only username check happened
            verify(userRepository).existsByUsername(registerRequest.username());
            verify(userRepository, never()).existsByEmail(anyString());
            verify(userService, never()).registerUser(any());
            verify(emailService, never()).sendVerificationEmail(any(), any());
            verify(tokenService, never()).generateToken(any());
        }

        @Test
        @DisplayName("Should throw DuplicateUserException when email already exists")
        void register_whenEmailExists_shouldThrowDuplicateUserException() {
             // Given
            when(userRepository.existsByUsername(registerRequest.username())).thenReturn(false);
            when(userRepository.existsByEmail(registerRequest.email())).thenReturn(true);

            // When & Then
            assertThatThrownBy(() -> authenticationService.register(registerRequest))
                .isInstanceOf(DuplicateUserException.class)
                .hasMessageContaining("Email already exists");

            // Verify username and email checks happened
            verify(userRepository).existsByUsername(registerRequest.username());
            verify(userRepository).existsByEmail(registerRequest.email());
            verify(userService, never()).registerUser(any());
            verify(emailService, never()).sendVerificationEmail(any(), any());
            verify(tokenService, never()).generateToken(any());
        }

        // Optional: Test case where email sending fails (exception is caught and logged, but registration succeeds)
        @Test
        @DisplayName("Should register successfully and return AuthResponse even if email sending fails")
        void register_whenEmailSendingFails_shouldStillRegisterAndReturnResponse() {
             // Given
            String verificationUrl = "http://localhost/verify?token=" + verificationToken;
            String jwtToken = "jwt.register.token.noemail";
            AuthResponse expectedResponse = AuthResponse.builder().token(jwtToken).username(registeredUser.getUsername()).build(); // Simplified

            when(userRepository.existsByUsername(registerRequest.username())).thenReturn(false);
            when(userRepository.existsByEmail(registerRequest.email())).thenReturn(false);
            when(userService.registerUser(registerRequest)).thenReturn(registeredUser);
            when(verificationService.buildVerificationUrl(verificationToken)).thenReturn(verificationUrl);

            // Mock email sending to throw an exception
            doThrow(new RuntimeException("SMTP server down")).when(emailService).sendVerificationEmail(registeredUser, verificationUrl);

            when(tokenService.generateToken(any(UserPrincipal.class))).thenReturn(jwtToken);
            dtoMapperMockedStatic.when(() -> DtoMapper.mapToAuthResponse(eq(registeredUser), eq(jwtToken))).thenReturn(expectedResponse);

            // When
            AuthResponse actualResponse = authenticationService.register(registerRequest);

            // Then
            // Registration and token generation should still succeed
            assertThat(actualResponse).isNotNull();
            assertThat(actualResponse.getToken()).isEqualTo(jwtToken);

            // Verify other interactions still happened
            verify(userRepository).existsByUsername(registerRequest.username());
            verify(userRepository).existsByEmail(registerRequest.email());
            verify(userService).registerUser(registerRequest);
            verify(verificationService).buildVerificationUrl(verificationToken);
            verify(emailService).sendVerificationEmail(registeredUser, verificationUrl); // Verify it was called
            verify(tokenService).generateToken(any(UserPrincipal.class));
            dtoMapperMockedStatic.verify(() -> DtoMapper.mapToAuthResponse(registeredUser, jwtToken));
        }
    }

    // --- Add test classes for other methods (logout, refreshToken, etc.) ---
} 