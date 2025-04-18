package dev.idachev.userservice.service;

import dev.idachev.userservice.exception.AuthenticationException;
import dev.idachev.userservice.exception.DuplicateUserException;
import dev.idachev.userservice.exception.UserNotFoundException;
import dev.idachev.userservice.model.User;
import dev.idachev.userservice.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

/**
 * Unit tests for the username change functionality in {@link AuthenticationService}.
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("AuthenticationService - Change Username Tests")
class AuthenticationServiceChangeUsernameUTest {

    @Mock
    private UserRepository userRepository;
    @Mock
    private PasswordEncoder passwordEncoder;
    @Mock
    private TokenService tokenService;

    @InjectMocks
    private AuthenticationService authenticationService;

    private final String CURRENT_USERNAME = "currentuser";
    private final String CURRENT_PASSWORD = "password123";
    private final String ENCODED_PASSWORD = "encodedPassword123";
    private final UUID USER_ID = UUID.randomUUID();
    private User testUser;

    @BeforeEach
    void setUp() {
        testUser = User.builder()
                .id(USER_ID)
                .username(CURRENT_USERNAME)
                .password(ENCODED_PASSWORD)
                .build();
    }

    @Test
    @DisplayName("Should change username successfully when input is valid")
    void changeUsername_withValidInput_shouldUpdateUsernameAndInvalidateTokens() {
        String newUsername = "newValidUsername1";

        when(userRepository.findByUsername(CURRENT_USERNAME)).thenReturn(Optional.of(testUser));
        when(passwordEncoder.matches(CURRENT_PASSWORD, ENCODED_PASSWORD)).thenReturn(true);
        when(userRepository.existsByUsername(newUsername)).thenReturn(false);
        when(userRepository.save(any(User.class))).thenAnswer(inv -> inv.getArgument(0));
        doNothing().when(tokenService).invalidateUserTokens(USER_ID);

        authenticationService.changeUsername(CURRENT_USERNAME, newUsername, CURRENT_PASSWORD);

        // Verify sequence and capture saved user
        verify(userRepository).findByUsername(CURRENT_USERNAME);
        verify(passwordEncoder).matches(CURRENT_PASSWORD, ENCODED_PASSWORD);
        verify(userRepository).existsByUsername(newUsername);

        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(userCaptor.capture());
        assertThat(userCaptor.getValue().getUsername()).isEqualTo(newUsername);

        verify(tokenService).invalidateUserTokens(USER_ID);
        verifyNoMoreInteractions(userRepository, passwordEncoder, tokenService);
    }

    @Test
    @DisplayName("Should throw IllegalArgumentException for blank input")
    void changeUsername_withBlankInput_shouldThrowIllegalArgumentException() {
        assertThatThrownBy(() -> authenticationService.changeUsername("", "new", "pass"))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("cannot be blank");

        assertThatThrownBy(() -> authenticationService.changeUsername("current", "", "pass"))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("cannot be blank");

        assertThatThrownBy(() -> authenticationService.changeUsername("current", "new", ""))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("cannot be blank");

        verifyNoInteractions(userRepository, passwordEncoder, tokenService);
    }

    @Test
    @DisplayName("Should throw IllegalArgumentException for invalid new username format")
    void changeUsername_withInvalidNewUsernameFormat_shouldThrowIllegalArgumentException() {
        String invalidUsername = "invalid username";

        assertThatThrownBy(() -> authenticationService.changeUsername(CURRENT_USERNAME, invalidUsername, CURRENT_PASSWORD))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Username must be 3-50 characters");

        verifyNoInteractions(userRepository, passwordEncoder, tokenService);
    }

    @Test
    @DisplayName("Should throw UserNotFoundException when current user not found")
    void changeUsername_whenCurrentUserNotFound_shouldThrowUserNotFoundException() {
        when(userRepository.findByUsername(CURRENT_USERNAME)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> authenticationService.changeUsername(CURRENT_USERNAME, "newuser", CURRENT_PASSWORD))
                .isInstanceOf(UserNotFoundException.class)
                .hasMessageContaining("User not found with username: " + CURRENT_USERNAME);

        verify(userRepository).findByUsername(CURRENT_USERNAME);
        verifyNoMoreInteractions(userRepository);
        verifyNoInteractions(passwordEncoder, tokenService);
    }

    @Test
    @DisplayName("Should do nothing if new username is same as current")
    void changeUsername_whenNewUsernameIsSame_shouldDoNothing() {
        authenticationService.changeUsername(CURRENT_USERNAME, CURRENT_USERNAME, CURRENT_PASSWORD);

        // Verify no interactions as the method should return early
        verifyNoInteractions(userRepository, passwordEncoder, tokenService);
    }

    @Test
    @DisplayName("Should throw AuthenticationException when current password is incorrect")
    void changeUsername_whenPasswordIncorrect_shouldThrowAuthenticationException() {
        String newUsername = "newValidUser2";
        when(userRepository.findByUsername(CURRENT_USERNAME)).thenReturn(Optional.of(testUser));
        when(passwordEncoder.matches(CURRENT_PASSWORD, ENCODED_PASSWORD)).thenReturn(false);

        assertThatThrownBy(() -> authenticationService.changeUsername(CURRENT_USERNAME, newUsername, CURRENT_PASSWORD))
                .isInstanceOf(AuthenticationException.class)
                .hasMessageContaining("Current password is incorrect");

        verify(userRepository).findByUsername(CURRENT_USERNAME);
        verify(passwordEncoder).matches(CURRENT_PASSWORD, ENCODED_PASSWORD);
        verifyNoMoreInteractions(userRepository, passwordEncoder);
        verifyNoInteractions(tokenService);
    }

    @Test
    @DisplayName("Should throw DuplicateUserException when new username already exists")
    void changeUsername_whenNewUsernameExists_shouldThrowDuplicateUserException() {
        String existingUsername = "alreadyTakenUser";
        when(userRepository.findByUsername(CURRENT_USERNAME)).thenReturn(Optional.of(testUser));
        when(passwordEncoder.matches(CURRENT_PASSWORD, ENCODED_PASSWORD)).thenReturn(true);
        when(userRepository.existsByUsername(existingUsername)).thenReturn(true);

        assertThatThrownBy(() -> authenticationService.changeUsername(CURRENT_USERNAME, existingUsername, CURRENT_PASSWORD))
                .isInstanceOf(DuplicateUserException.class)
                .hasMessageContaining("Username already exists");

        verify(userRepository).findByUsername(CURRENT_USERNAME);
        verify(passwordEncoder).matches(CURRENT_PASSWORD, ENCODED_PASSWORD);
        verify(userRepository).existsByUsername(existingUsername);
        verifyNoMoreInteractions(userRepository, passwordEncoder);
        verifyNoInteractions(tokenService);
    }
} 