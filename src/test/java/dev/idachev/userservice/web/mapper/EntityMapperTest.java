package dev.idachev.userservice.web.mapper;

import dev.idachev.userservice.model.Role;
import dev.idachev.userservice.model.User;
import dev.idachev.userservice.web.dto.RegisterRequest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

@DisplayName("EntityMapper Tests")
@ExtendWith(MockitoExtension.class) // Initialize mocks
class EntityMapperTest {

    @Mock
    private PasswordEncoder mockPasswordEncoder;

    @Test
    @DisplayName("mapToNewUser maps RegisterRequest correctly")
    void mapToNewUser_Success() {
        RegisterRequest request = new RegisterRequest("newUser", "new@example.com", "plainPassword");
        String verificationToken = "verify-me";
        String encodedPassword = "encodedPassword123";

        // Mock the password encoder
        when(mockPasswordEncoder.encode(request.password())).thenReturn(encodedPassword);

        User newUser = EntityMapper.mapToNewUser(request, mockPasswordEncoder, verificationToken);

        assertThat(newUser).isNotNull();
        assertThat(newUser.getUsername()).isEqualTo(request.username());
        assertThat(newUser.getEmail()).isEqualTo(request.email());
        assertThat(newUser.getPassword()).isEqualTo(encodedPassword); // Check encoded password
        assertThat(newUser.getRole()).isEqualTo(Role.USER); // Default role
        assertThat(newUser.isEnabled()).isFalse(); // Default enabled status
        assertThat(newUser.isBanned()).isFalse(); // Default banned status
        assertThat(newUser.getVerificationToken()).isEqualTo(verificationToken);
        assertThat(newUser.getCreatedOn()).isNotNull();
        assertThat(newUser.getUpdatedOn()).isNotNull();
        assertThat(newUser.getCreatedOn()).isEqualTo(newUser.getUpdatedOn()); // Should be same initially
    }

    @Test
    @DisplayName("mapToNewUser throws NullPointerException for null request")
    void mapToNewUser_NullRequest() {
        assertThatThrownBy(() -> EntityMapper.mapToNewUser(null, mockPasswordEncoder, "token"))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("Cannot map null request");
    }

    @Test
    @DisplayName("mapToNewUser throws NullPointerException for null encoder")
    void mapToNewUser_NullEncoder() {
        RegisterRequest request = new RegisterRequest("newUser", "new@example.com", "plainPassword");
        assertThatThrownBy(() -> EntityMapper.mapToNewUser(request, null, "token"))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("PasswordEncoder cannot be null");
    }

    @Test
    @DisplayName("mapToNewUser throws NullPointerException for null token")
    void mapToNewUser_NullToken() {
        RegisterRequest request = new RegisterRequest("newUser", "new@example.com", "plainPassword");
        assertThatThrownBy(() -> EntityMapper.mapToNewUser(request, mockPasswordEncoder, null))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("Verification token cannot be null");
    }
} 