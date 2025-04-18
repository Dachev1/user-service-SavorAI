package dev.idachev.userservice.service;

import dev.idachev.userservice.exception.AuthenticationException;
import dev.idachev.userservice.exception.UserNotFoundException;
import dev.idachev.userservice.model.User;
import dev.idachev.userservice.repository.UserRepository;
import dev.idachev.userservice.web.dto.UserStatusResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("AuthenticationService - Check User Status Tests")
@MockitoSettings(strictness = Strictness.LENIENT)
class AuthenticationServiceCheckUserStatusUTest {

    @Mock
    private UserRepository userRepository;

    @InjectMocks
    private AuthenticationService authenticationService;

    @BeforeEach
    void setUp() {
        // Setup might not be needed anymore unless we add complex state
    }

    @Test
    @DisplayName("Should return UserStatusResponse when user found by username")
    void checkUserStatus_whenUserFoundByUsername_shouldReturnStatus() {
        // Given
        String username = "statususer";
        User user = User.builder()
                .id(UUID.randomUUID())
                .username(username)
                .enabled(true)
                .banned(false)
                .build();

        lenient().when(userRepository.findByUsername(username)).thenReturn(Optional.of(user));
        lenient().when(userRepository.findByEmail(username)).thenReturn(Optional.empty());

        // When
        UserStatusResponse actualResponse = authenticationService.checkUserStatus(username);

        // Then
        assertThat(actualResponse).isNotNull();
        assertThat(actualResponse.getUsername()).isEqualTo(username);
        assertThat(actualResponse.isEnabled()).isTrue();
        assertThat(actualResponse.isBanned()).isFalse();

        verify(userRepository).findByUsername(username);
        verify(userRepository, never()).findByEmail(username);
        // No DtoMapper interaction to verify
    }

    @Test
    @DisplayName("Should return UserStatusResponse when user found by email")
    void checkUserStatus_whenUserFoundByEmail_shouldReturnStatus() {
        // Given
        String email = "status@test.com";
         User user = User.builder()
                .id(UUID.randomUUID())
                .username("userFoundByEmail")
                .email(email)
                .enabled(false)
                .banned(true)
                .build();

        when(userRepository.findByUsername(email)).thenReturn(Optional.empty());
        when(userRepository.findByEmail(email)).thenReturn(Optional.of(user));

        // When
        UserStatusResponse actualResponse = authenticationService.checkUserStatus(email);

        // Then
        assertThat(actualResponse).isNotNull();
        assertThat(actualResponse.getUsername()).isEqualTo("userFoundByEmail");
        assertThat(actualResponse.isEnabled()).isFalse();
        assertThat(actualResponse.isBanned()).isTrue();

        verify(userRepository).findByUsername(email);
        verify(userRepository).findByEmail(email);
        // No DtoMapper interaction to verify
    }

    @Test
    @DisplayName("Should throw AuthenticationException when user not found")
    void checkUserStatus_whenUserNotFound_shouldThrowAuthenticationException() {
        // Given
        String identifier = "notfounduser";

        when(userRepository.findByUsername(identifier)).thenReturn(Optional.empty());
        when(userRepository.findByEmail(identifier)).thenReturn(Optional.empty());

        // When & Then
        // AuthenticationService.findUserByIdentifier throws AuthenticationException if not found
        assertThatThrownBy(() -> authenticationService.checkUserStatus(identifier))
            .isInstanceOf(AuthenticationException.class)
            .hasMessageContaining("Invalid credentials");

        verify(userRepository).findByUsername(identifier);
        verify(userRepository).findByEmail(identifier);
        // No DtoMapper interaction to verify
    }
} 