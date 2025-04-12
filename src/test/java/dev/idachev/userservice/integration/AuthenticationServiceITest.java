package dev.idachev.userservice.integration;

import dev.idachev.userservice.model.User;
import dev.idachev.userservice.repository.UserRepository;
import dev.idachev.userservice.service.AuthenticationService;
import dev.idachev.userservice.service.EmailService;
import dev.idachev.userservice.service.TokenService;
import dev.idachev.userservice.service.UserService;
import dev.idachev.userservice.web.dto.AuthResponse;
import dev.idachev.userservice.web.dto.RegisterRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.UUID;
import java.util.concurrent.CompletableFuture;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class AuthenticationServiceITest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private AuthenticationManager authenticationManager;

    @Mock
    private TokenService tokenService;
    
    @Mock
    private UserDetailsService userDetailsService;
    
    @Mock
    private PasswordEncoder passwordEncoder;
    
    @Mock
    private EmailService emailService;
    
    @Mock
    private UserService userService;
    
    @Captor
    private ArgumentCaptor<User> userCaptor;
    
    private AuthenticationService authenticationService;
    
    private RegisterRequest standardRegisterRequest;
    
    @BeforeEach
    void setUp() {
        authenticationService = new AuthenticationService(
            userRepository,
            authenticationManager,
            tokenService,
            userDetailsService,
            passwordEncoder,
            emailService,
            userService
        );
            
        standardRegisterRequest = RegisterRequest.builder()
                .username("testuser")
                .email("test@example.com")
                .password("Password123!")
                .build();
                
        // Mock userService behavior to return a valid user
        when(userService.registerUser(any())).thenAnswer(invocation -> {
            RegisterRequest request = invocation.getArgument(0);
            return User.builder()
                    .id(UUID.randomUUID())
                    .username(request.getUsername())
                    .email(request.getEmail())
                    .password("encoded_password")
                    .enabled(false)
                    .verificationToken(UUID.randomUUID().toString())
                    .build();
        });
        
        // Mock email service to return CompletableFuture
        when(emailService.sendVerificationEmailAsync(any(User.class)))
            .thenReturn(CompletableFuture.completedFuture(null));
    }

    @Test
    void testUserRegistration() {
        // Register a user
        AuthResponse response = authenticationService.register(standardRegisterRequest);
        
        // Verify user service was called
        verify(userService).registerUser(any(RegisterRequest.class));
        
        // Verify email service was called
        verify(emailService).sendVerificationEmailAsync(any(User.class));
        
        // Verify response
        assertThat(response).isNotNull();
        assertThat(response.isSuccess()).isTrue();
        assertThat(response.getMessage()).contains("Registration successful");
    }
} 