package dev.idachev.userservice.service;

import dev.idachev.userservice.exception.AuthenticationException;
import dev.idachev.userservice.exception.ResourceNotFoundException;
import dev.idachev.userservice.mapper.EntityMapper;
import dev.idachev.userservice.model.User;
import dev.idachev.userservice.repository.UserRepository;
import dev.idachev.userservice.security.UserPrincipal;
import dev.idachev.userservice.web.dto.AuthResponse;
import dev.idachev.userservice.web.dto.GenericResponse;
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
    private dev.idachev.userservice.service.UserDetailsService userDetailsService;
    
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

    @BeforeEach
    void setUp() {
        SecurityContextHolder.setContext(securityContext);

        // Manually create the service with all dependencies
        authenticationService = new AuthenticationService(
            userRepository,
            authenticationManager,
            tokenService,
            userDetailsService,
            passwordEncoder,
            emailService,
            userService
        );

        testUser = User.builder()
                .id(UUID.randomUUID())
                .username("testuser")
                .email("test@example.com")
                .password("encoded_password")
                .enabled(true) // Assume enabled for sign-in tests
                .createdOn(LocalDateTime.now())
                .updatedOn(LocalDateTime.now())
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

        // Mock dependencies
        when(passwordEncoder.encode(anyString())).thenReturn("encoded_password");
        when(emailService.generateVerificationToken()).thenReturn(UUID.randomUUID().toString());
        
        // Mock userService.registerUser method
        when(userService.registerUser(any(RegisterRequest.class))).thenReturn(testUser);
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void givenValidCredentials_whenSignIn_thenReturnAuthResponseWithToken() {
        // Given
        when(userRepository.findByUsername(anyString())).thenReturn(Optional.of(testUser));
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class))).thenReturn(authentication);
        when(authentication.getPrincipal()).thenReturn(new UserPrincipal(testUser));
        when(tokenService.generateToken(any(UserDetails.class))).thenReturn(testToken);
        when(userRepository.findById(any(UUID.class))).thenReturn(Optional.of(testUser));

        // When
        AuthResponse response = authenticationService.signIn(signInRequest);

        // Then
        assertNotNull(response);
        assertEquals(testToken, response.getToken());
        assertEquals(testUser.getUsername(), response.getUsername());
        assertTrue(response.isSuccess());
        verify(userRepository).save(testUser); // Check if lastLogin is updated
    }

    @Test
    void givenNonexistentUser_whenSignIn_thenThrowAuthenticationException() {
        // Given
        when(userRepository.findByUsername(anyString())).thenReturn(Optional.empty());
        when(userRepository.findByEmail(anyString())).thenReturn(Optional.empty());

        // When & Then
        assertThrows(ResourceNotFoundException.class, () -> authenticationService.signIn(signInRequest));
    }

    @Test
    void givenInvalidCredentials_whenSignIn_thenThrowAuthenticationException() {
        // Given
        when(userRepository.findByUsername(anyString())).thenReturn(Optional.of(testUser));
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenThrow(new BadCredentialsException("Invalid credentials"));

        // When & Then
        assertThrows(BadCredentialsException.class, () -> authenticationService.signIn(signInRequest));
    }

    @Test
    void givenUserNotEnabled_whenSignIn_thenThrowAuthenticationException() {
        // Given
        testUser.setEnabled(false);
        when(userRepository.findByUsername(anyString())).thenReturn(Optional.of(testUser));

        // When & Then
        assertThrows(AuthenticationException.class, () -> authenticationService.signIn(signInRequest));
    }

    @Test
    void givenValidRegistrationRequest_whenRegister_thenReturnSuccessResponse() {
        // Given
        User savedUser = EntityMapper.mapToNewUser(validRegisterRequest, passwordEncoder, "token");
        savedUser.setId(UUID.randomUUID()); // Simulate persistence

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
    void givenExistingUsername_whenRegister_thenThrowDuplicateUserException() {
        // Given
        when(userRepository.existsByUsername(anyString())).thenReturn(true);

        // When/Then
        assertThrows(dev.idachev.userservice.exception.DuplicateUserException.class, () -> 
            authenticationService.register(validRegisterRequest));
        
        verify(userService, never()).registerUser(any(RegisterRequest.class));
    }

    @Test
    void givenExistingEmail_whenRegister_thenThrowDuplicateUserException() {
        // Given
        when(userRepository.existsByEmail(anyString())).thenReturn(true);

        // When/Then
        assertThrows(dev.idachev.userservice.exception.DuplicateUserException.class, () -> 
            authenticationService.register(validRegisterRequest));
        
        verify(userService, never()).registerUser(any(RegisterRequest.class));
    }

    // Tests for token refresh
    @Test
    void refreshToken_Success() {
        // Given
        String authHeader = "Bearer " + testToken;
        UserDetails userDetails = new UserPrincipal(testUser);
        when(tokenService.extractUserId(anyString())).thenReturn(testUser.getId());
        when(userDetailsService.loadUserById(any(UUID.class))).thenReturn(userDetails);
        when(tokenService.generateToken(any(UserDetails.class))).thenReturn("new.token");

        // When
        AuthResponse response = authenticationService.refreshToken(authHeader);

        // Then
        assertTrue(response.isSuccess());
        assertEquals("new.token", response.getToken());
        verify(tokenService).blacklistToken(authHeader);
    }

    @Test
    void refreshToken_InvalidHeader() {
        // Given
        String invalidHeader = "InvalidHeader";

        // When/Then
        assertThrows(AuthenticationException.class, () ->
                authenticationService.refreshToken(invalidHeader));
    }

    // Tests for logout
    @Test
    void givenValidUserId_whenLogout_thenUpdateUserStatus() {
        // Given
        when(userRepository.findById(any(UUID.class))).thenReturn(Optional.of(testUser));

        // When
        authenticationService.logout(testUser.getId());

        // Then
        verify(userRepository).save(any(User.class));
        assertFalse(testUser.isLoggedIn());
    }

    @Test
    void givenNullUserId_whenLogout_thenDoNothing() {
        // When
        authenticationService.logout((UUID) null);

        // Then
        verify(userRepository, never()).save(any(User.class));
    }
}
