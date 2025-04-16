package dev.idachev.userservice.service;

import dev.idachev.userservice.exception.AuthenticationException;
import dev.idachev.userservice.exception.DuplicateUserException;
import dev.idachev.userservice.exception.InvalidTokenException;
import dev.idachev.userservice.exception.UserNotFoundException;
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
class AuthenticationServiceUTest {

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
    private String authToken;
    
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
                .username("testuser")
                .email("test@example.com")
                .password("encodedPassword")
                .role(Role.USER)
                .enabled(true)
                .banned(false)
                .createdOn(LocalDateTime.now())
                .updatedOn(LocalDateTime.now())
                .build();
                
        authToken = "valid.jwt.token";
    }
    
    @Test
    @DisplayName("Should register new user successfully when valid request is provided")
    void should_RegisterNewUser_When_ValidRequestIsProvided() {
        // Given
        RegisterRequest request = new RegisterRequest(
                "newuser", 
                "new@example.com", 
                "Password123"
        );
        
        when(userRepository.existsByUsername(request.getUsername())).thenReturn(false);
        when(userRepository.existsByEmail(request.getEmail())).thenReturn(false);
        when(userService.registerUser(request)).thenReturn(testUser);
        when(tokenService.generateToken(any(UserPrincipal.class))).thenReturn(authToken);
        
        // When
        AuthResponse response = authService.register(request);
        
        // Then
        verify(emailService).sendVerificationEmailAsync(testUser);
        
        assertThat(response).isNotNull();
        assertThat(response.getToken()).isEqualTo(authToken);
        assertThat(response.getUser().getId()).isEqualTo(userId);
    }
    
    @Test
    @DisplayName("Should throw DuplicateUserException when registering with existing username")
    void should_ThrowDuplicateUserException_When_RegisteringWithExistingUsername() {
        // Given
        RegisterRequest request = new RegisterRequest(
                "existingUser", 
                "new@example.com", 
                "Password123"
        );
        
        when(userRepository.existsByUsername(request.getUsername())).thenReturn(true);
        
        // When/Then
        assertThatThrownBy(() -> authService.register(request))
                .isInstanceOf(DuplicateUserException.class)
                .hasMessageContaining("Username already exists");
    }
    
    @Test
    @DisplayName("Should throw DuplicateUserException when registering with existing email")
    void should_ThrowDuplicateUserException_When_RegisteringWithExistingEmail() {
        // Given
        RegisterRequest request = new RegisterRequest(
                "newuser", 
                "existing@example.com", 
                "Password123"
        );
        
        when(userRepository.existsByUsername(request.getUsername())).thenReturn(false);
        when(userRepository.existsByEmail(request.getEmail())).thenReturn(true);
        
        // When/Then
        assertThatThrownBy(() -> authService.register(request))
                .isInstanceOf(DuplicateUserException.class)
                .hasMessageContaining("Email already exists");
    }
    
    @Test
    @DisplayName("Should authenticate user successfully when valid credentials are provided")
    void should_AuthenticateUser_When_ValidCredentialsAreProvided() {
        // Given
        SignInRequest request = new SignInRequest("testuser", "password123");
        
        when(userRepository.findByUsername(request.getIdentifier())).thenReturn(Optional.of(testUser));
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(authentication);
        when(authentication.getPrincipal()).thenReturn(new UserPrincipal(testUser));
        when(tokenService.generateToken(any(UserPrincipal.class))).thenReturn(authToken);
        
        // When
        AuthResponse response = authService.signIn(request);
        
        // Then
        verify(authenticationManager).authenticate(authTokenCaptor.capture());
        UsernamePasswordAuthenticationToken authRequest = authTokenCaptor.getValue();
        
        assertThat(authRequest.getPrincipal()).isEqualTo("testuser");
        assertThat(authRequest.getCredentials()).isEqualTo("password123");
        
        assertThat(response).isNotNull();
        assertThat(response.getToken()).isEqualTo(authToken);
        assertThat(response.getUser().getId()).isEqualTo(userId);
    }
    
    @Test
    @DisplayName("Should authenticate user by email when valid credentials are provided")
    void should_AuthenticateUserByEmail_When_ValidCredentialsAreProvided() {
        // Given
        SignInRequest request = new SignInRequest("test@example.com", "password123");
        
        when(userRepository.findByUsername(request.getIdentifier())).thenReturn(Optional.empty());
        when(userRepository.findByEmail(request.getIdentifier())).thenReturn(Optional.of(testUser));
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(authentication);
        when(authentication.getPrincipal()).thenReturn(new UserPrincipal(testUser));
        when(tokenService.generateToken(any(UserPrincipal.class))).thenReturn(authToken);
        
        // When
        AuthResponse response = authService.signIn(request);
        
        // Then
        verify(authenticationManager).authenticate(authTokenCaptor.capture());
        
        assertThat(response).isNotNull();
        assertThat(response.getToken()).isEqualTo(authToken);
        assertThat(response.getUser().getId()).isEqualTo(userId);
    }
    
    @Test
    @DisplayName("Should throw AuthenticationException when user account is not verified")
    void should_ThrowAuthenticationException_When_UserAccountIsNotVerified() {
        // Given
        SignInRequest request = new SignInRequest("testuser", "password123");
        testUser.setEnabled(false);
        
        when(userRepository.findByUsername(request.getIdentifier())).thenReturn(Optional.of(testUser));
        
        // When/Then
        assertThatThrownBy(() -> authService.signIn(request))
                .isInstanceOf(AuthenticationException.class)
                .hasMessageContaining("Account not verified");
    }
    
    @Test
    @DisplayName("Should throw AuthenticationException when user account is banned")
    void should_ThrowAuthenticationException_When_UserAccountIsBanned() {
        // Given
        SignInRequest request = new SignInRequest("testuser", "password123");
        testUser.setBanned(true);
        
        when(userRepository.findByUsername(request.getIdentifier())).thenReturn(Optional.of(testUser));
        
        // When/Then
        assertThatThrownBy(() -> authService.signIn(request))
                .isInstanceOf(AuthenticationException.class)
                .hasMessageContaining("banned");
    }
    
    @Test
    @DisplayName("Should throw AuthenticationException when authentication fails with bad credentials")
    void should_ThrowAuthenticationException_When_AuthenticationFailsWithBadCredentials() {
        // Given
        SignInRequest request = new SignInRequest("testuser", "wrongpassword");
        
        when(userRepository.findByUsername(request.getIdentifier())).thenReturn(Optional.of(testUser));
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenThrow(new BadCredentialsException("Bad credentials"));
        
        // When/Then
        assertThatThrownBy(() -> authService.signIn(request))
                .isInstanceOf(AuthenticationException.class)
                .hasMessageContaining("Invalid credentials");
    }
    
    @Test
    @DisplayName("Should logout user successfully when valid token is provided")
    void should_LogoutUser_When_ValidTokenIsProvided() {
        // Given
        String authHeader = "Bearer " + authToken;
        
        when(tokenService.extractUserId(authToken)).thenReturn(userId);
        when(userRepository.findById(userId)).thenReturn(Optional.of(testUser));
        
        // When
        GenericResponse response = authService.logout(authHeader);
        
        // Then
        verify(tokenService).blacklistToken(authToken);
        verify(userRepository).save(userCaptor.capture());
        User savedUser = userCaptor.getValue();
        
        assertThat(savedUser.isLoggedIn()).isFalse();
        assertThat(response.isSuccess()).isTrue();
        assertThat(response.getMessage()).contains("Successfully logged out");
    }
    
    @Test
    @DisplayName("Should refresh token successfully when valid token is provided")
    void should_RefreshToken_When_ValidTokenIsProvided() {
        // Given
        String authHeader = "Bearer " + authToken;
        String newToken = "new.jwt.token";
        
        when(tokenService.extractUserId(authToken)).thenReturn(userId);
        when(tokenService.isTokenBlacklisted(authToken)).thenReturn(false);
        when(userRepository.findById(userId)).thenReturn(Optional.of(testUser));
        when(tokenService.generateToken(any(UserPrincipal.class))).thenReturn(newToken);
        
        // When
        AuthResponse response = authService.refreshToken(authHeader);
        
        // Then
        verify(tokenService).blacklistToken(authToken);
        
        assertThat(response).isNotNull();
        assertThat(response.getToken()).isEqualTo(newToken);
        assertThat(response.getUser().getId()).isEqualTo(userId);
    }
    
    @Test
    @DisplayName("Should throw InvalidTokenException when token is blacklisted during refresh")
    void should_ThrowInvalidTokenException_When_TokenIsBlacklistedDuringRefresh() {
        // Given
        String authHeader = "Bearer " + authToken;
        
        when(tokenService.isTokenBlacklisted(authToken)).thenReturn(true);
        
        // When/Then
        assertThatThrownBy(() -> authService.refreshToken(authHeader))
                .isInstanceOf(AuthenticationException.class)
                .hasMessageContaining("blacklisted");
    }
    
    @Test
    @DisplayName("Should change username successfully when valid credentials are provided")
    void should_ChangeUsername_When_ValidCredentialsAreProvided() {
        // Given
        String currentUsername = "testuser";
        String newUsername = "newusername";
        String password = "password123";
        
        when(userRepository.findByUsername(currentUsername)).thenReturn(Optional.of(testUser));
        when(passwordEncoder.matches(password, testUser.getPassword())).thenReturn(true);
        when(userRepository.existsByUsername(newUsername)).thenReturn(false);
        
        // When
        GenericResponse response = authService.changeUsername(currentUsername, newUsername, password);
        
        // Then
        verify(userRepository).save(userCaptor.capture());
        User savedUser = userCaptor.getValue();
        verify(tokenService).invalidateUserTokens(userId);
        
        assertThat(savedUser.getUsername()).isEqualTo(newUsername);
        assertThat(response.isSuccess()).isTrue();
        assertThat(response.getMessage()).contains("Username updated successfully");
    }
    
    @Test
    @DisplayName("Should throw AuthenticationException when changing username with incorrect password")
    void should_ThrowAuthenticationException_When_ChangingUsernameWithIncorrectPassword() {
        // Given
        String currentUsername = "testuser";
        String newUsername = "newusername";
        String wrongPassword = "wrongpassword";
        
        when(userRepository.findByUsername(currentUsername)).thenReturn(Optional.of(testUser));
        when(passwordEncoder.matches(wrongPassword, testUser.getPassword())).thenReturn(false);
        
        // When/Then
        assertThatThrownBy(() -> authService.changeUsername(currentUsername, newUsername, wrongPassword))
                .isInstanceOf(AuthenticationException.class)
                .hasMessageContaining("Current password is incorrect");
    }
    
    @Test
    @DisplayName("Should throw DuplicateUserException when changing to existing username")
    void should_ThrowDuplicateUserException_When_ChangingToExistingUsername() {
        // Given
        String currentUsername = "testuser";
        String existingUsername = "existingUser";
        String password = "password123";
        
        when(userRepository.findByUsername(currentUsername)).thenReturn(Optional.of(testUser));
        when(passwordEncoder.matches(password, testUser.getPassword())).thenReturn(true);
        when(userRepository.existsByUsername(existingUsername)).thenReturn(true);
        
        // When/Then
        assertThatThrownBy(() -> authService.changeUsername(currentUsername, existingUsername, password))
                .isInstanceOf(DuplicateUserException.class)
                .hasMessageContaining("Username already exists");
    }
    
    @Test
    @DisplayName("Should check user ban status successfully")
    void should_CheckUserBanStatus_Successfully() {
        // Given
        String username = "testuser";
        
        when(userRepository.findByUsername(username)).thenReturn(Optional.of(testUser));
        
        // When
        Map<String, Object> result = authService.checkUserBanStatus(username);
        
        // Then
        assertThat(result).isNotNull()
                .containsEntry("username", "testuser")
                .containsEntry("banned", false)
                .containsEntry("enabled", true);
    }
    
    @Test
    @DisplayName("Should throw UserNotFoundException when checking ban status for non-existent user")
    void should_ThrowUserNotFoundException_When_CheckingBanStatusForNonExistentUser() {
        // Given
        String nonExistentUsername = "nonExistentUser";
        
        when(userRepository.findByUsername(nonExistentUsername)).thenReturn(Optional.empty());
        when(userRepository.findByEmail(nonExistentUsername)).thenReturn(Optional.empty());
        
        // When/Then
        assertThatThrownBy(() -> authService.checkUserBanStatus(nonExistentUsername))
                .isInstanceOf(UserNotFoundException.class);
    }
} 