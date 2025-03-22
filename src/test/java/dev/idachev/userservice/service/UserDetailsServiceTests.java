package dev.idachev.userservice.service;

import dev.idachev.userservice.model.User;
import dev.idachev.userservice.repository.UserRepository;
import dev.idachev.userservice.security.UserPrincipal;
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
        assertTrue(result instanceof UserPrincipal);
        UserPrincipal userPrincipal = (UserPrincipal) result;
        assertEquals(user, userPrincipal.user());
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
        assertTrue(result instanceof UserPrincipal);
        UserPrincipal userPrincipal = (UserPrincipal) result;
        assertEquals(user, userPrincipal.user());
        verify(userRepository).findByEmail(identifier);
        verify(userRepository).findByUsername(identifier);
    }

    @Test
    void givenNonExistentIdentifier_whenLoadUserByUsername_thenThrowUsernameNotFoundException() {
        // Given
        String identifier = "nonexistent";

        when(userRepository.findByEmail(identifier)).thenReturn(Optional.empty());
        when(userRepository.findByUsername(identifier)).thenReturn(Optional.empty());

        // When & Then
        assertThrows(UsernameNotFoundException.class, () -> userDetailsService.loadUserByUsername(identifier));
        verify(userRepository).findByEmail(identifier);
        verify(userRepository).findByUsername(identifier);
    }
}