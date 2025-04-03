package dev.idachev.userservice.config;

import dev.idachev.userservice.model.Role;
import dev.idachev.userservice.model.User;
import dev.idachev.userservice.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AdminUserInitTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @InjectMocks
    private AdminUserInit adminUserInit;

    private final String testUsername = "Ivan";
    private final String testEmail = "pffe3e@gmail.com";
    private final String testPassword = "123456789";
    private final String encodedPassword = "encoded_password";

    @Test
    void whenAdminUserDoesNotExist_thenCreateIt() {
        // Given
        when(userRepository.existsByUsername(testUsername)).thenReturn(false);
        when(userRepository.existsByEmail(testEmail)).thenReturn(false);
        when(passwordEncoder.encode(testPassword)).thenReturn(encodedPassword);

        // When
        adminUserInit.run(new String[]{});

        // Then
        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(userCaptor.capture());
        
        User savedUser = userCaptor.getValue();
        assertEquals(testUsername, savedUser.getUsername());
        assertEquals(testEmail, savedUser.getEmail());
        assertEquals(encodedPassword, savedUser.getPassword());
        assertEquals(Role.ADMIN, savedUser.getRole());
        assertTrue(savedUser.isEnabled());
        assertNotNull(savedUser.getCreatedOn());
        assertNotNull(savedUser.getUpdatedOn());
        verify(passwordEncoder).encode(testPassword);
    }

    @Test
    void whenAdminUserExists_thenDoNotCreateIt() {
        // Given
        when(userRepository.existsByUsername(testUsername)).thenReturn(true);

        // When
        adminUserInit.run(new String[]{});

        // Then
        verify(userRepository, never()).save(any(User.class));
        verify(passwordEncoder, never()).encode(anyString());
    }

    @Test
    void whenAdminEmailExists_thenDoNotCreateIt() {
        // Given
        when(userRepository.existsByUsername(testUsername)).thenReturn(false);
        when(userRepository.existsByEmail(testEmail)).thenReturn(true);

        // When
        adminUserInit.run(new String[]{});

        // Then
        verify(userRepository, never()).save(any(User.class));
        verify(passwordEncoder, never()).encode(anyString());
    }
} 