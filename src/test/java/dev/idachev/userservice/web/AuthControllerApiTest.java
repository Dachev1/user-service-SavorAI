package dev.idachev.userservice.web;

import dev.idachev.userservice.model.Role;
import dev.idachev.userservice.service.AuthenticationService;
import dev.idachev.userservice.web.dto.AuthResponse;
import dev.idachev.userservice.web.dto.GenericResponse;
import dev.idachev.userservice.web.dto.RegisterRequest;
import dev.idachev.userservice.web.dto.SignInRequest;
import dev.idachev.userservice.web.dto.UserResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthControllerApiTest {

    @Mock
    private AuthenticationService authService;

    @InjectMocks
    private AuthController authController;

    private UUID userId;
    private RegisterRequest registerRequest;
    private SignInRequest signInRequest;
    private AuthResponse authResponse;
    private UserResponse userResponse;
    private String authToken;
    private MockHttpServletRequest httpServletRequest;

    @BeforeEach
    void setUp() {
        // Setup mock request context
        httpServletRequest = new MockHttpServletRequest();
        httpServletRequest.addHeader("Authorization", "Bearer test.jwt.token");
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(httpServletRequest));

        // Initialize test data
        userId = UUID.randomUUID();
        authToken = "test.jwt.token";
        
        registerRequest = new RegisterRequest(
                "testuser",
                "test@example.com",
                "Password123"
        );
        
        signInRequest = new SignInRequest(
                "testuser",
                "Password123"
        );
        
        userResponse = UserResponse.builder()
                .id(userId)
                .username("testuser")
                .email("test@example.com")
                .verified(true)
                .role("USER")
                .createdOn(LocalDateTime.now())
                .build();
                
        authResponse = AuthResponse.builder()
                .token(authToken)
                .user(userResponse)
                .build();
    }

    @Test
    @DisplayName("Should register new user when valid request is provided")
    void should_RegisterNewUser_When_ValidRequestIsProvided() {
        // Given
        when(authService.register(any(RegisterRequest.class))).thenReturn(authResponse);

        // When
        ResponseEntity<AuthResponse> response = authController.signup(registerRequest);

        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        assertThat(response.getBody()).isEqualTo(authResponse);
        assertThat(response.getBody().getToken()).isEqualTo(authToken);
        assertThat(response.getBody().getUser().getId()).isEqualTo(userId);
        verify(authService).register(registerRequest);
    }

    @Test
    @DisplayName("Should authenticate user when valid credentials are provided")
    void should_AuthenticateUser_When_ValidCredentialsAreProvided() {
        // Given
        when(authService.signIn(any(SignInRequest.class))).thenReturn(authResponse);

        // When
        ResponseEntity<AuthResponse> response = authController.signin(signInRequest);

        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isEqualTo(authResponse);
        assertThat(response.getBody().getToken()).isEqualTo(authToken);
        assertThat(response.getBody().getUser().getId()).isEqualTo(userId);
        verify(authService).signIn(signInRequest);
    }

    @Test
    @DisplayName("Should log out user when valid token is provided")
    void should_LogoutUser_When_ValidTokenIsProvided() {
        // Given
        String authHeader = "Bearer " + authToken;
        GenericResponse expectedResponse = GenericResponse.builder()
                .success(true)
                .message("Successfully logged out")
                .status(HttpStatus.OK.value())
                .build();
        
        when(authService.logout(authHeader)).thenReturn(expectedResponse);

        // When
        ResponseEntity<GenericResponse> response = authController.logout(authHeader);

        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isEqualTo(expectedResponse);
        assertThat(response.getBody().isSuccess()).isTrue();
        assertThat(response.getBody().getMessage()).contains("Successfully logged out");
        verify(authService).logout(authHeader);
    }

    @Test
    @DisplayName("Should refresh token when valid token is provided")
    void should_RefreshToken_When_ValidTokenIsProvided() {
        // Given
        when(authService.refreshToken(anyString())).thenReturn(authResponse);

        // When
        ResponseEntity<AuthResponse> response = authController.refreshToken(httpServletRequest);

        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isEqualTo(authResponse);
        assertThat(response.getBody().getToken()).isEqualTo(authToken);
        verify(authService).refreshToken(anyString());
    }

    @Test
    @DisplayName("Should check user status when username is provided")
    void should_CheckUserStatus_When_UsernameIsProvided() {
        // Given
        String username = "testuser";
        Map<String, Object> expectedStatus = new HashMap<>();
        expectedStatus.put("username", username);
        expectedStatus.put("banned", false);
        expectedStatus.put("verified", true);
        
        when(authService.checkUserBanStatus(username)).thenReturn(expectedStatus);

        // When
        ResponseEntity<Map<String, Object>> response = authController.checkUserStatus(username);

        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isEqualTo(expectedStatus);
        assertThat(response.getBody().get("username")).isEqualTo(username);
        assertThat(response.getBody().get("banned")).isEqualTo(false);
        verify(authService).checkUserBanStatus(username);
    }
} 