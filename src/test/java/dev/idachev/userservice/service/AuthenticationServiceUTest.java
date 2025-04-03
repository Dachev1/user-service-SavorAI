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
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
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
    private Authentication authentication;
    @Mock
    private SecurityContext securityContext;

    @InjectMocks
    private AuthenticationService authenticationService;

    private User testUser;
    private RegisterRequest validRegisterRequest;
    private SignInRequest signInRequest;
    private String testToken;

    @BeforeEach
    void setUp() {
        SecurityContextHolder.setContext(securityContext);

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

        // Mocks for dependencies
        lenient().when(passwordEncoder.encode(anyString())).thenReturn("encoded_password");
        lenient().when(emailService.generateVerificationToken()).thenReturn(UUID.randomUUID().toString());
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
        assertThrows(AuthenticationException.class, () -> authenticationService.signIn(signInRequest));
    }

    @Test
    void givenInvalidCredentials_whenSignIn_thenThrowAuthenticationException() {
        // Given
        when(userRepository.findByUsername(anyString())).thenReturn(Optional.of(testUser));
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenThrow(new BadCredentialsException("Invalid credentials"));

        // When & Then
        assertThrows(AuthenticationException.class, () -> authenticationService.signIn(signInRequest));
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
        when(userRepository.save(any(User.class))).thenReturn(savedUser);
        when(emailService.sendVerificationEmailAsync(any(User.class))).thenReturn(CompletableFuture.completedFuture(null));

        // When
        AuthResponse response = authenticationService.register(validRegisterRequest);

        // Then
        assertNotNull(response);
        assertTrue(response.isSuccess());
        assertEquals("Registration successful! Please check your email to verify your account.", response.getMessage());
        verify(userRepository).save(any(User.class));
        verify(emailService).sendVerificationEmailAsync(any(User.class));
    }

    @Test
    void givenExistingUsername_whenRegister_thenThrowDuplicateUserException() {
        // Given
        when(userRepository.existsByUsername(anyString())).thenReturn(true);

        // When/Then
        assertThrows(dev.idachev.userservice.exception.DuplicateUserException.class, () -> 
            authenticationService.register(validRegisterRequest));
        
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    void givenExistingEmail_whenRegister_thenThrowDuplicateUserException() {
        // Given
        when(userRepository.existsByEmail(anyString())).thenReturn(true);

        // When/Then
        assertThrows(dev.idachev.userservice.exception.DuplicateUserException.class, () -> 
            authenticationService.register(validRegisterRequest));
        
        verify(userRepository, never()).save(any(User.class));
    }

    // --- Remove tests for methods moved to other services --- 
    // - verifyEmail tests removed
    // - verifyEmailAndGetResponse tests removed
    // - resendVerificationEmail tests removed
    // - resendVerificationEmailWithResponse tests removed
    // - getVerificationStatus tests removed
    // - getCurrentUser tests removed
    // - getCurrentUserInfo tests removed

    // Keep tests checking for conflicts with the pre-defined admin user
    @Test
    void givenAdminUserExists_whenRegisterWithSameUsername_thenThrowDuplicateUserException() {
        // Given
        String adminUsername = "Ivan";
        RegisterRequest request = RegisterRequest.builder()
                .username(adminUsername)
                .email("another@example.com")
                .password("password123")
                .build();

        when(userRepository.existsByUsername(adminUsername)).thenReturn(true);

        // When/Then
        assertThrows(dev.idachev.userservice.exception.DuplicateUserException.class, () -> 
            authenticationService.register(request));
        
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    void givenAdminUserExists_whenRegisterWithSameEmail_thenThrowDuplicateUserException() {
        // Given
        String adminEmail = "pffe3e@gmail.com";
        RegisterRequest request = RegisterRequest.builder()
                .username("newuser")
                .email(adminEmail)
                .password("password123")
                .build();

        when(userRepository.existsByEmail(adminEmail)).thenReturn(true);

        // When/Then
        assertThrows(dev.idachev.userservice.exception.DuplicateUserException.class, () -> 
            authenticationService.register(request));
        
        verify(userRepository, never()).save(any(User.class));
    }

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

    @Test
    void findByUsernameOrEmail_ByUsername() {
        // Given
        when(userRepository.findByUsername(anyString())).thenReturn(Optional.of(testUser));

        // When
        User result = authenticationService.findByUsernameOrEmail("testuser");

        // Then
        assertEquals(testUser, result);
    }

    @Test
    void findByUsernameOrEmail_ByEmail() {
        // Given
        when(userRepository.findByUsername(anyString())).thenReturn(Optional.empty());
        when(userRepository.findByEmail(anyString())).thenReturn(Optional.of(testUser));

        // When
        User result = authenticationService.findByUsernameOrEmail("test@example.com");

        // Then
        assertEquals(testUser, result);
    }

    @Test
    void findByUsernameOrEmail_NotFound() {
        // Given
        when(userRepository.findByUsername(anyString())).thenReturn(Optional.empty());
        when(userRepository.findByEmail(anyString())).thenReturn(Optional.empty());

        // When/Then
        assertThrows(ResourceNotFoundException.class, () ->
                authenticationService.findByUsernameOrEmail("nonexistent"));
    }

    @Test
    void givenValidUserId_whenLogout_thenUpdateUserStatus() {
        // Given
        when(userRepository.findById(any(UUID.class))).thenReturn(Optional.of(testUser));

        // When
        authenticationService.logout(testUser.getId());

        // Then
        verify(userRepository).save(any(User.class));
    }

    @Test
    void givenNullUserId_whenLogout_thenDoNothing() {
        // When
        authenticationService.logout(null);

        // Then
        verify(userRepository, never()).save(any(User.class));
    }
}
