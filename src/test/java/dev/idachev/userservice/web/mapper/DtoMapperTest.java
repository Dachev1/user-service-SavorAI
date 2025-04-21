package dev.idachev.userservice.web.mapper;

import dev.idachev.userservice.model.Role;
import dev.idachev.userservice.model.User;
import dev.idachev.userservice.web.dto.AuthResponse;
import dev.idachev.userservice.web.dto.GenericResponse;
import dev.idachev.userservice.web.dto.UserResponse;
import dev.idachev.userservice.web.dto.VerificationResponse;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("DtoMapper Tests")
class DtoMapperTest {

    private User createTestUser() {
        return User.builder()
                .id(UUID.randomUUID())
                .username("testUser")
                .email("test@example.com")
                .password("encodedPassword")
                .role(Role.USER)
                .enabled(true)
                .banned(false)
                .verificationToken(null) // Assuming verified
                .createdOn(LocalDateTime.now().minusDays(1))
                .lastLogin(LocalDateTime.now())
                .build();
    }

    @Test
    @DisplayName("mapToUserResponse maps correctly")
    void mapToUserResponse_Success() {
        User user = createTestUser();
        UserResponse response = DtoMapper.mapToUserResponse(user);

        assertThat(response).isNotNull();
        assertThat(response.getId()).isEqualTo(user.getId());
        assertThat(response.getUsername()).isEqualTo(user.getUsername());
        assertThat(response.getEmail()).isEqualTo(user.getEmail());
        assertThat(response.getRole()).isEqualTo(user.getRole().name());
        assertThat(response.isBanned()).isEqualTo(user.isBanned());
        assertThat(response.isEnabled()).isEqualTo(user.isEnabled());
        assertThat(response.isVerificationPending()).isEqualTo(user.isVerificationPending());
        assertThat(response.getCreatedOn()).isEqualTo(user.getCreatedOn());
        assertThat(response.getLastLogin()).isEqualTo(user.getLastLogin());
    }

    @Test
    @DisplayName("mapToUserResponse throws NullPointerException for null user")
    void mapToUserResponse_NullUser() {
        assertThatThrownBy(() -> DtoMapper.mapToUserResponse(null))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("Cannot map null user");
    }

    @Test
    @DisplayName("mapToAuthResponse (User, token) maps correctly")
    void mapToAuthResponse_WithToken_Success() {
        User user = createTestUser();
        String token = "test-jwt-token";
        AuthResponse response = DtoMapper.mapToAuthResponse(user, token);

        assertThat(response).isNotNull();
        assertThat(response.getToken()).isEqualTo(token);
        assertThat(response.isSuccess()).isTrue();
        assertThat(response.getUser()).isNotNull();
        assertThat(response.getUser().getUsername()).isEqualTo(user.getUsername());
        assertThat(response.getUsername()).isEqualTo(user.getUsername()); // Also check top-level fields
        assertThat(response.getEmail()).isEqualTo(user.getEmail());
        assertThat(response.getRole()).isEqualTo(user.getRole().name());
    }

    @Test
    @DisplayName("mapToAuthResponse (User, token) handles null token")
    void mapToAuthResponse_WithNullToken() {
        User user = createTestUser();
        AuthResponse response = DtoMapper.mapToAuthResponse(user, null);

        assertThat(response.getToken()).isNotNull().isEmpty();
    }

    @Test
    @DisplayName("mapToAuthResponse (User, success, message) maps correctly")
    void mapToAuthResponse_WithMessage_Success() {
        User user = createTestUser();
        AuthResponse response = DtoMapper.mapToAuthResponse(user, true, "Login OK");

        assertThat(response).isNotNull();
        assertThat(response.isSuccess()).isTrue();
        assertThat(response.getMessage()).isEqualTo("Login OK");
        assertThat(response.getUser()).isNotNull();
        assertThat(response.getUsername()).isEqualTo(user.getUsername());
        assertThat(response.getToken()).isNotNull().isEmpty(); // No token in this overload
    }

    @Test
    @DisplayName("mapToAuthResponse (success, message) maps correctly")
    void mapToAuthResponse_Simple_Success() {
        AuthResponse response = DtoMapper.mapToAuthResponse(false, "Error occurred");

        assertThat(response).isNotNull();
        assertThat(response.isSuccess()).isFalse();
        assertThat(response.getMessage()).isEqualTo("Error occurred");
        assertThat(response.getUser()).isNull();
        assertThat(response.getUsername()).isNotNull().isEmpty();
        assertThat(response.getToken()).isNotNull().isEmpty();
    }

    @Test
    @DisplayName("mapToVerificationResponse maps correctly")
    void mapToVerificationResponse_Success() {
        User user = createTestUser();
        VerificationResponse response = DtoMapper.mapToVerificationResponse(user, true, "Verified");

        assertThat(response).isNotNull();
        assertThat(response.isSuccess()).isTrue();
        assertThat(response.getMessage()).isEqualTo("Verified");
        assertThat(response.getData()).isNotNull();
        assertThat(((UserResponse) response.getData()).getUsername()).isEqualTo(user.getUsername());
        assertThat(response.getTimestamp()).isNotNull();
    }

    @Test
    @DisplayName("mapToGenericResponse maps correctly")
    void mapToGenericResponse_Success() {
        GenericResponse response = DtoMapper.mapToGenericResponse(200, "OK");

        assertThat(response).isNotNull();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getMessage()).isEqualTo("OK");
        assertThat(response.isSuccess()).isTrue();
        assertThat(response.getTimestamp()).isNotNull();
    }

    @Test
    @DisplayName("mapToGenericResponse handles error status")
    void mapToGenericResponse_Error() {
        GenericResponse response = DtoMapper.mapToGenericResponse(404, "Not Found");

        assertThat(response).isNotNull();
        assertThat(response.getStatus()).isEqualTo(404);
        assertThat(response.getMessage()).isEqualTo("Not Found");
        assertThat(response.isSuccess()).isFalse(); // Success should be false for 4xx/5xx
        assertThat(response.getTimestamp()).isNotNull();
    }
} 