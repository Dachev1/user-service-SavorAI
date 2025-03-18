package dev.idachev.userservice.service;

import dev.idachev.userservice.model.User;
import dev.idachev.userservice.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class UserDetailsServiceTests {

    @Mock
    private UserRepository userRepository;

    @InjectMocks
    private UserDetailsService userDetailsService;

    @Test
    void givenExistingEmail_whenLoadUserByUsername_thenReturnUserDetails() {
        // Given
        String identifier = "test@example.com";
        User user = User.builder()
                .email(identifier)
                .build();

        when(userRepository.findByEmail(identifier)).thenReturn(Optional.of(user));

        // When
        UserDetails result = userDetailsService.loadUserByUsername(identifier);

        // Then
        assertNotNull(result);
        assertEquals(user, result);
        verify(userRepository).findByEmail(identifier);
        verify(userRepository, never()).findByUsername(anyString());
    }

    @Test
    void givenExistingUsername_whenLoadUserByUsername_thenReturnUserDetails() {
        // Given
        String identifier = "testuser";
        User user = User.builder()
                .username(identifier)
                .build();

        when(userRepository.findByEmail(identifier)).thenReturn(Optional.empty());
        when(userRepository.findByUsername(identifier)).thenReturn(Optional.of(user));

        // When
        UserDetails result = userDetailsService.loadUserByUsername(identifier);

        // Then
        assertNotNull(result);
        assertEquals(user, result);
        verify(userRepository).findByEmail(identifier);
        verify(userRepository).findByUsername(identifier);
    }

    @Test
    void givenNonexistentIdentifier_whenLoadUserByUsername_thenThrowUsernameNotFoundException() {
        // Given
        String identifier = "nonexistent";

        when(userRepository.findByEmail(identifier)).thenReturn(Optional.empty());
        when(userRepository.findByUsername(identifier)).thenReturn(Optional.empty());

        // When & Then
        UsernameNotFoundException exception = assertThrows(UsernameNotFoundException.class,
                () -> userDetailsService.loadUserByUsername(identifier));

        assertTrue(exception.getMessage().contains(identifier));
        verify(userRepository).findByEmail(identifier);
        verify(userRepository).findByUsername(identifier);
    }
}