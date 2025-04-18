package dev.idachev.userservice.service;

import dev.idachev.userservice.exception.AuthenticationException;
import dev.idachev.userservice.exception.DuplicateUserException;
import dev.idachev.userservice.exception.InvalidTokenException;
import dev.idachev.userservice.exception.UserNotFoundException;
import dev.idachev.userservice.exception.AccountVerificationException;
import dev.idachev.userservice.model.Role;
import dev.idachev.userservice.model.User;
import dev.idachev.userservice.repository.UserRepository;
import dev.idachev.userservice.security.UserPrincipal;
import dev.idachev.userservice.web.dto.AuthResponse;
import dev.idachev.userservice.web.dto.GenericResponse;
import dev.idachev.userservice.web.dto.RegisterRequest;
import dev.idachev.userservice.web.dto.SignInRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthenticationServiceTest {

    // Constants for tests
    private static final String TEST_USERNAME = "testuser";
    private static final String TEST_EMAIL = "test@example.com";
    private static final String TEST_PASSWORD = "password123";
    private static final String ENCODED_PASSWORD = "encodedPassword";
    private static final String AUTH_TOKEN = "valid.jwt.token";
    private static final String NEW_USERNAME = "newUsername";

    @Mock
    private UserRepository userRepository;
    
    @Mock
    private AuthenticationManager authenticationManager;
    
    @Mock
    private TokenService tokenService;
    
    @Mock
    private PasswordEncoder passwordEncoder;
    
    @Mock
    private EmailService emailService;
    
    @Mock
    private UserService userService;
    
    @Mock
    private Authentication authentication;
    
    @Captor
    private ArgumentCaptor<User> userCaptor;
    
    @Captor
    private ArgumentCaptor<UsernamePasswordAuthenticationToken> authTokenCaptor;
    
    private AuthenticationService authService;
    
    private UUID userId;
    private User testUser;
    
    @BeforeEach
    void setUp() {
        authService = new AuthenticationService(
            userRepository,
            authenticationManager,
            tokenService,
            passwordEncoder,
            emailService,
            userService
        );
        
        userId = UUID.randomUUID();
        testUser = User.builder()
                .id(userId)
                .username(TEST_USERNAME)
                .email(TEST_EMAIL)
                .password(ENCODED_PASSWORD)
                .role(Role.USER)
                .enabled(true)
                .banned(false)
                .createdOn(LocalDateTime.now())
                .updatedOn(LocalDateTime.now())
                .build();
    }
    
    @Test
    @DisplayName("Register new user with valid request")
    void registerNewUser_validRequest_succeeds() {
        // Given
        RegisterRequest request = new RegisterRequest(
                "newuser", 
                "new@example.com", 
                TEST_PASSWORD
        );
        
        when(userRepository.existsByUsername(request.getUsername())).thenReturn(false);
        when(userRepository.existsByEmail(request.getEmail())).thenReturn(false);
        when(userService.registerUser(request)).thenReturn(testUser);
        when(tokenService.generateToken(any(UserPrincipal.class))).thenReturn(AUTH_TOKEN);
        
        // When
        AuthResponse response = authService.register(request);
        
        // Then
        verify(emailService).sendVerificationEmailAsync(testUser);
        
        assertThat(response).isNotNull();
        assertThat(response.getToken()).isEqualTo(AUTH_TOKEN);
        assertThat(response.getUser().getId()).isEqualTo(userId);
    }
    
    @Test
    @DisplayName("Register with existing username throws exception")
    void registerUser_existingUsername_throwsDuplicateUserException() {
        // Given
        RegisterRequest request = new RegisterRequest(
                "existingUser", 
                "new@example.com", 
                TEST_PASSWORD
        );
        
        when(userRepository.existsByUsername(request.getUsername())).thenReturn(true);
        
        // When/Then
        assertThatThrownBy(() -> authService.register(request))
                .isInstanceOf(DuplicateUserException.class)
                .hasMessageContaining("Username already exists");
                
        verify(userRepository, never()).save(any(User.class));
        verify(emailService, never()).sendVerificationEmailAsync(any(User.class));
    }
    
    @Test
    @DisplayName("Register with existing email throws exception")
    void registerUser_existingEmail_throwsDuplicateUserException() {
        // Given
        RegisterRequest request = new RegisterRequest(
                "newuser", 
                "existing@example.com", 
                TEST_PASSWORD
        );
        
        when(userRepository.existsByUsername(request.getUsername())).thenReturn(false);
        when(userRepository.existsByEmail(request.getEmail())).thenReturn(true);
        
        // When/Then
        assertThatThrownBy(() -> authService.register(request))
                .isInstanceOf(DuplicateUserException.class)
                .hasMessageContaining("Email already exists");
                
        verify(userRepository, never()).save(any(User.class));
        verify(emailService, never()).sendVerificationEmailAsync(any(User.class));
    }
    
    @Test
    @DisplayName("Sign in with valid username succeeds")
    void signIn_validUsername_succeeds() {
        // Given
        SignInRequest request = new SignInRequest(TEST_USERNAME, TEST_PASSWORD);
        
        when(userRepository.findByUsername(request.getIdentifier())).thenReturn(Optional.of(testUser));
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(authentication);
        when(authentication.getPrincipal()).thenReturn(new UserPrincipal(testUser));
        when(tokenService.generateToken(any(UserPrincipal.class))).thenReturn(AUTH_TOKEN);
        
        // When
        AuthResponse response = authService.signIn(request);
        
        // Then
        verify(authenticationManager).authenticate(authTokenCaptor.capture());
        UsernamePasswordAuthenticationToken authRequest = authTokenCaptor.getValue();
        
        assertThat(authRequest.getPrincipal()).isEqualTo(TEST_USERNAME);
        assertThat(authRequest.getCredentials()).isEqualTo(TEST_PASSWORD);
        assertThat(response).isNotNull();
        assertThat(response.getToken()).isEqualTo(AUTH_TOKEN);
        assertThat(response.getUser().getId()).isEqualTo(userId);
    }
    
    @Test
    @DisplayName("Sign in with valid email succeeds")
    void signIn_validEmail_succeeds() {
        // Given
        SignInRequest request = new SignInRequest(TEST_EMAIL, TEST_PASSWORD);
        
        when(userRepository.findByUsername(request.getIdentifier())).thenReturn(Optional.empty());
        when(userRepository.findByEmail(request.getIdentifier())).thenReturn(Optional.of(testUser));
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(authentication);
        when(authentication.getPrincipal()).thenReturn(new UserPrincipal(testUser));
        when(tokenService.generateToken(any(UserPrincipal.class))).thenReturn(AUTH_TOKEN);
        
        // When
        AuthResponse response = authService.signIn(request);
        
        // Then
        verify(authenticationManager).authenticate(authTokenCaptor.capture());
        
        assertThat(response).isNotNull();
        assertThat(response.getToken()).isEqualTo(AUTH_TOKEN);
        assertThat(response.getUser().getId()).isEqualTo(userId);
    }
    
    @Test
    @DisplayName("Sign in with unverified account throws exception")
    void signIn_unverifiedAccount_throwsAuthenticationException() {
        // Given
        SignInRequest request = new SignInRequest(TEST_USERNAME, TEST_PASSWORD);
        testUser.setEnabled(false);
        
        when(userRepository.findByUsername(request.getIdentifier())).thenReturn(Optional.of(testUser));
        
        // When/Then
        assertThatThrownBy(() -> authService.signIn(request))
                .isInstanceOf(AccountVerificationException.class)
                .hasMessageContaining("Account not verified");
                
        verify(authenticationManager, never()).authenticate(any());
    }
    
    @Test
    @DisplayName("Sign in with banned account throws exception")
    void signIn_bannedAccount_throwsAuthenticationException() {
        // Given
        SignInRequest request = new SignInRequest(TEST_USERNAME, TEST_PASSWORD);
        testUser.setBanned(true);
        
        when(userRepository.findByUsername(request.getIdentifier())).thenReturn(Optional.of(testUser));
        
        // When/Then
        assertThatThrownBy(() -> authService.signIn(request))
                .isInstanceOf(AuthenticationException.class)
                .hasMessageContaining("banned");
                
        verify(authenticationManager, never()).authenticate(any());
    }
    
    @Test
    @DisplayName("Sign in with bad credentials throws exception")
    void signIn_badCredentials_throwsAuthenticationException() {
        // Given
        SignInRequest request = new SignInRequest(TEST_USERNAME, "wrongPassword");
        
        when(userRepository.findByUsername(request.getIdentifier())).thenReturn(Optional.of(testUser));
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenThrow(new BadCredentialsException("Bad credentials"));
        
        // When/Then
        assertThatThrownBy(() -> authService.signIn(request))
                .isInstanceOf(AuthenticationException.class)
                .hasMessageContaining("Invalid credentials");
    }
    
    @Test
    @DisplayName("Logout with valid token succeeds")
    void logout_validToken_succeeds() {
        // Given
        String authHeader = "Bearer " + AUTH_TOKEN;
        String extractedToken = AUTH_TOKEN;

        when(tokenService.extractUserId(extractedToken)).thenReturn(userId);
        when(tokenService.blacklistToken(extractedToken)).thenReturn(true);
        when(userRepository.findById(userId)).thenReturn(Optional.of(testUser));
        
        // When
        GenericResponse response = authService.logout(authHeader);
        
        // Then
        verify(tokenService).blacklistToken(extractedToken);
        
        assertThat(response).isNotNull();
        assertThat(response.isSuccess()).isTrue();
        assertThat(response.getMessage()).contains("logged out");

        verify(userRepository).save(userCaptor.capture());
        assertThat(userCaptor.getValue().isLoggedIn()).isFalse();
    }
    
    @Test
    @DisplayName("Refresh token with valid token succeeds")
    void refreshToken_validToken_succeeds() {
        // Given
        String token = "Bearer " + AUTH_TOKEN;
        when(tokenService.isTokenBlacklisted(AUTH_TOKEN)).thenReturn(false);
        when(tokenService.extractUserId(AUTH_TOKEN)).thenReturn(userId);
        when(userRepository.findById(userId)).thenReturn(Optional.of(testUser));
        when(tokenService.generateToken(any(UserPrincipal.class))).thenReturn("new.jwt.token");
        
        // When
        AuthResponse response = authService.refreshToken(token);
        
        // Then
        verify(tokenService).blacklistToken(AUTH_TOKEN);
        verify(tokenService).generateToken(any(UserPrincipal.class));
        
        assertThat(response).isNotNull();
        assertThat(response.getToken()).isEqualTo("new.jwt.token");
        assertThat(response.getUser().getId()).isEqualTo(userId);
    }
    
    @Test
    @DisplayName("Refresh blacklisted token throws exception")
    void refreshToken_blacklistedToken_throwsAuthenticationException() {
        // Given
        String token = "Bearer " + AUTH_TOKEN;
        when(tokenService.isTokenBlacklisted(AUTH_TOKEN)).thenReturn(true);
        
        // When/Then
        assertThatThrownBy(() -> authService.refreshToken(token))
                .isInstanceOf(AuthenticationException.class)
                .hasMessageContaining("blacklisted");
                
        verify(tokenService, never()).generateToken(any());
    }
    
    @Test
    @DisplayName("Change username with valid credentials succeeds")
    void changeUsername_validCredentials_succeeds() {
        // Given
        String currentUsername = TEST_USERNAME;
        String newUsername = NEW_USERNAME;
        String password = TEST_PASSWORD;
        
        when(userRepository.findByUsername(currentUsername)).thenReturn(Optional.of(testUser));
        when(userRepository.existsByUsername(newUsername)).thenReturn(false);
        when(passwordEncoder.matches(password, testUser.getPassword())).thenReturn(true);
        when(userRepository.save(any(User.class))).thenReturn(testUser);
        
        // When
        GenericResponse response = authService.changeUsername(currentUsername, newUsername, password);
        
        // Then
        verify(userRepository).save(userCaptor.capture());
        User savedUser = userCaptor.getValue();
        
        assertThat(savedUser.getUsername()).isEqualTo(newUsername);
        assertThat(response).isNotNull();
        assertThat(response.isSuccess()).isTrue();
        assertThat(response.getMessage()).isEqualTo("Username updated successfully");
    }
    
    @Test
    @DisplayName("Change username with incorrect password throws exception")
    void changeUsername_incorrectPassword_throwsAuthenticationException() {
        // Given
        String currentUsername = TEST_USERNAME;
        String newUsername = NEW_USERNAME;
        String password = "wrongPassword";
        
        when(userRepository.findByUsername(currentUsername)).thenReturn(Optional.of(testUser));
        when(passwordEncoder.matches(password, testUser.getPassword())).thenReturn(false);
        
        // When/Then
        assertThatThrownBy(() -> authService.changeUsername(currentUsername, newUsername, password))
                .isInstanceOf(AuthenticationException.class)
                .hasMessageContaining("Current password is incorrect");
                
        verify(userRepository, never()).save(any(User.class));
    }
    
    @Test
    @DisplayName("Change to existing username throws exception")
    void changeUsername_existingUsername_throwsDuplicateUserException() {
        // Given
        String currentUsername = TEST_USERNAME;
        String newUsername = NEW_USERNAME;
        String password = TEST_PASSWORD;
        
        when(userRepository.findByUsername(currentUsername)).thenReturn(Optional.of(testUser));
        when(userRepository.existsByUsername(newUsername)).thenReturn(true);
        when(passwordEncoder.matches(password, testUser.getPassword())).thenReturn(true);
        
        // When/Then
        assertThatThrownBy(() -> authService.changeUsername(currentUsername, newUsername, password))
                .isInstanceOf(DuplicateUserException.class)
                .hasMessageContaining("Username already exists");
                
        verify(userRepository, never()).save(any(User.class));
    }
    
    @Test
    @DisplayName("Check user ban status retrieves correct status")
    void checkUserBanStatus_existingUser_retrievesCorrectStatus() {
        // Given
        String identifier = TEST_USERNAME;
        
        when(userRepository.findByUsername(identifier)).thenReturn(Optional.of(testUser));
        
        // When
        Map<String, Object> response = authService.checkUserBanStatus(identifier);
        
        // Then
        assertThat(response).isNotNull();
        assertThat(response.get("banned")).isEqualTo(false);
    }
    
    @Test
    @DisplayName("Check ban status for non-existent user throws exception")
    void checkUserBanStatus_nonExistentUser_throwsUserNotFoundException() {
        // Given
        String nonExistentIdentifier = "nonexistent";
        when(userRepository.findByUsername(nonExistentIdentifier)).thenReturn(Optional.empty());
        when(userRepository.findByEmail(nonExistentIdentifier)).thenReturn(Optional.empty());
        
        // When/Then
        assertThatThrownBy(() -> authService.checkUserBanStatus(nonExistentIdentifier))
                .isInstanceOf(AuthenticationException.class)
                .hasMessageContaining("Invalid credentials");
    }
} 