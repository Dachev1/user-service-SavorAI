package dev.idachev.userservice.service;

import dev.idachev.userservice.exception.AuthenticationException;
import dev.idachev.userservice.exception.DuplicateUserException;
import dev.idachev.userservice.exception.ResourceNotFoundException;
import dev.idachev.userservice.model.User;
import dev.idachev.userservice.repository.UserRepository;
import dev.idachev.userservice.security.UserPrincipal;
import dev.idachev.userservice.web.dto.AuthResponse;
import dev.idachev.userservice.web.dto.RegisterRequest;
import dev.idachev.userservice.web.dto.SignInRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
public class AuthenticationServiceUTest {

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
    private UserDetailsService userDetailsService;
    @Mock
    private UserService userService;
    @Mock
    private Authentication authentication;
    @Mock
    private SecurityContext securityContext;

    private AuthenticationService authenticationService;
    private User testUser;
    private RegisterRequest validRegisterRequest;
    private SignInRequest signInRequest;
    private String testToken;
    private UUID testUserId;

    @BeforeEach
    void setUp() {
        SecurityContextHolder.setContext(securityContext);

        authenticationService = new AuthenticationService(
            userRepository,
            authenticationManager,
            tokenService,
            userDetailsService,
            passwordEncoder,
            emailService,
            userService
        );

        // Test data setup
        testUserId = UUID.randomUUID();
        testUser = User.builder()
                .id(testUserId)
                .username("testuser")
                .email("test@example.com")
                .password("encoded_password")
                .enabled(true)
                .banned(false)
                .createdOn(LocalDateTime.now())
                .build();

        validRegisterRequest = RegisterRequest.builder()
                .username("testuser")
                .email("test@example.com")
                .password("password123")
                .build();

        signInRequest = SignInRequest.builder()
                .identifier("testuser")
                .password("password123")
                .build();

        testToken = "test.jwt.token";
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    // AUTHENTICATION TESTS

    @Test
    void signIn_validCredentials_returnsAuthResponseWithToken() {
        // Given
        when(userRepository.findByUsername(anyString())).thenReturn(Optional.of(testUser));
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class))).thenReturn(authentication);
        when(authentication.getPrincipal()).thenReturn(new UserPrincipal(testUser));
        when(tokenService.generateToken(any(UserDetails.class))).thenReturn(testToken);

        // When
        AuthResponse response = authenticationService.signIn(signInRequest);

        // Then
        assertNotNull(response);
        assertEquals(testToken, response.getToken());
        assertEquals(testUser.getUsername(), response.getUsername());
        assertTrue(response.isSuccess());
        verify(userRepository).save(testUser);
    }

    @Test
    void signIn_bannedUser_throwsAuthenticationException() {
        // Given
        User bannedUser = User.builder()
                .id(testUserId)
                .username("testuser")
                .email("test@example.com")
                .password("encoded_password")
                .enabled(true)
                .banned(true)
                .createdOn(LocalDateTime.now())
                .build();
        when(userRepository.findByUsername(anyString())).thenReturn(Optional.of(bannedUser));

        // When & Then
        assertThrows(AuthenticationException.class, () -> 
            authenticationService.signIn(signInRequest));
    }

    @Test
    void signIn_nonexistentUser_throwsResourceNotFoundException() {
        // Given
        when(userRepository.findByUsername(anyString())).thenReturn(Optional.empty());
        when(userRepository.findByEmail(anyString())).thenReturn(Optional.empty());

        // When & Then
        assertThrows(ResourceNotFoundException.class, () -> 
            authenticationService.signIn(signInRequest));
    }

    @Test
    void signIn_invalidCredentials_throwsBadCredentialsException() {
        // Given
        when(userRepository.findByUsername(anyString())).thenReturn(Optional.of(testUser));
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenThrow(new BadCredentialsException("Invalid credentials"));

        // When & Then
        assertThrows(BadCredentialsException.class, () -> 
            authenticationService.signIn(signInRequest));
    }

    @Test
    void signIn_userNotEnabled_throwsAuthenticationException() {
        // Given
        User disabledUser = User.builder()
                .id(testUserId)
                .username("testuser")
                .email("test@example.com")
                .password("encoded_password")
                .enabled(false)
                .banned(false)
                .createdOn(LocalDateTime.now())
                .build();
        when(userRepository.findByUsername(anyString())).thenReturn(Optional.of(disabledUser));

        // When & Then
        assertThrows(AuthenticationException.class, () -> 
            authenticationService.signIn(signInRequest));
    }

    // REGISTRATION TESTS

    @Test
    void register_validRequest_returnsSuccessResponse() {
        // Given
        User savedUser = User.builder()
            .id(UUID.randomUUID())
            .username("testuser")
            .email("test@example.com")
            .password("encoded_password")
            .build();
        
        when(userRepository.existsByUsername(anyString())).thenReturn(false);
        when(userRepository.existsByEmail(anyString())).thenReturn(false);
        when(userService.registerUser(any(RegisterRequest.class))).thenReturn(savedUser);
        when(emailService.sendVerificationEmailAsync(any(User.class))).thenReturn(CompletableFuture.completedFuture(null));

        // When
        AuthResponse response = authenticationService.register(validRegisterRequest);

        // Then
        assertNotNull(response);
        assertTrue(response.isSuccess());
        assertEquals("Registration successful! Please check your email to verify your account.", response.getMessage());
        verify(userService).registerUser(any(RegisterRequest.class));
        verify(emailService).sendVerificationEmailAsync(any(User.class));
    }

    @Test
    void register_existingUsername_throwsDuplicateUserException() {
        // Given
        when(userRepository.existsByUsername(anyString())).thenReturn(true);

        // When & Then
        assertThrows(DuplicateUserException.class, () -> 
            authenticationService.register(validRegisterRequest));
        
        verify(userService, never()).registerUser(any(RegisterRequest.class));
    }

    @Test
    void register_existingEmail_throwsDuplicateUserException() {
        // Given
        when(userRepository.existsByEmail(anyString())).thenReturn(true);

        // When & Then
        assertThrows(DuplicateUserException.class, () -> 
            authenticationService.register(validRegisterRequest));
        
        verify(userService, never()).registerUser(any(RegisterRequest.class));
    }

    // TOKEN MANAGEMENT TESTS

    @Test
    void refreshToken_validToken_returnsNewToken() {
        // Given
        String authHeader = "Bearer " + testToken;
        String jwtToken = testToken;  // The token without the "Bearer " prefix
        UserDetails userDetails = new UserPrincipal(testUser);
        
        when(tokenService.isTokenBlacklisted(jwtToken)).thenReturn(false);
        when(tokenService.extractUserId(jwtToken)).thenReturn(testUser.getId());
        when(userRepository.findById(testUser.getId())).thenReturn(Optional.of(testUser));
        when(tokenService.generateToken(any(UserDetails.class))).thenReturn("new.token");

        // When
        AuthResponse response = authenticationService.refreshToken(authHeader);

        // Then
        assertTrue(response.isSuccess());
        assertEquals("new.token", response.getToken());
        verify(tokenService).blacklistToken(jwtToken);
    }

    @Test
    void refreshToken_invalidHeader_throwsAuthenticationException() {
        // When & Then
        assertThrows(AuthenticationException.class, () -> 
            authenticationService.refreshToken("InvalidHeader"));
    }

    @Test
    void logout_validUserId_updatesUserStatus() {
        // Given
        String token = testToken;
        when(tokenService.extractUserId(anyString())).thenReturn(testUserId);
        when(userRepository.findById(any(UUID.class))).thenReturn(Optional.of(testUser));

        // When
        authenticationService.logout(token);

        // Then
        verify(tokenService).blacklistToken(token);
        verify(userRepository).findById(testUserId);
        verify(userRepository).save(testUser);
    }

    @Test
    void logout_nullUserId_doesNothing() {
        // When
        authenticationService.logout((String) null);

        // Then
        verify(tokenService, never()).blacklistToken(anyString());
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    void logout_withToken_blacklistsTokenAndUpdatesUser() {
        // Given
        String token = "Bearer " + testToken;
        String tokenWithoutBearer = testToken;
        when(tokenService.extractUserId(anyString())).thenReturn(testUserId);
        when(userRepository.findById(any(UUID.class))).thenReturn(Optional.of(testUser));

        // When
        authenticationService.logout(token);

        // Then
        verify(tokenService).blacklistToken(tokenWithoutBearer);
        verify(userRepository).save(testUser);
    }

    @Test
    void logout_withNullToken_doesNothing() {
        // When
        authenticationService.logout((String) null);

        // Then
        verify(tokenService, never()).blacklistToken(anyString());
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    void checkUserBanStatus_bannedUser_returnsTrue() {
        // Given
        User bannedUser = User.builder()
                .id(testUserId)
                .username("testuser")
                .email("test@example.com")
                .banned(true)
                .build();
        when(userRepository.findByUsername(anyString())).thenReturn(Optional.of(bannedUser));

        // When
        var result = authenticationService.checkUserBanStatus("testuser");

        // Then
        assertTrue((Boolean) result.get("banned"));
    }

    @Test
    void checkUserBanStatus_nonBannedUser_returnsFalse() {
        // Given
        User nonBannedUser = User.builder()
                .id(testUserId)
                .username("testuser")
                .email("test@example.com")
                .banned(false)
                .build();
        when(userRepository.findByUsername(anyString())).thenReturn(Optional.of(nonBannedUser));

        // When
        var result = authenticationService.checkUserBanStatus("testuser");

        // Then
        assertFalse((Boolean) result.get("banned"));
    }
}
