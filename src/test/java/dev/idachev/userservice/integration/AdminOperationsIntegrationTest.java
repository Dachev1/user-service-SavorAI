package dev.idachev.userservice.integration;

import dev.idachev.userservice.model.Role;
import dev.idachev.userservice.model.User;
import dev.idachev.userservice.repository.UserRepository;
import dev.idachev.userservice.web.dto.AuthResponse;
import dev.idachev.userservice.web.dto.BanStatusResponse;
import dev.idachev.userservice.web.dto.RoleUpdateResponse;
import dev.idachev.userservice.web.dto.SignInRequest;
import dev.idachev.userservice.web.dto.UserResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
class AdminOperationsIntegrationTest {

    @Autowired
    private TestRestTemplate restTemplate;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    private User adminUser;
    private User regularUser;
    private String adminToken;

    @BeforeEach
    void setUp() {
        // Create admin user
        adminUser = new User();
        adminUser.setUsername("admin");
        adminUser.setEmail("admin@example.com");
        adminUser.setPassword(passwordEncoder.encode("AdminPass123!"));
        adminUser.setRole(Role.ADMIN);
        adminUser.setEnabled(true);
        adminUser.setBanned(false);
        adminUser = userRepository.save(adminUser);

        // Create regular user
        regularUser = new User();
        regularUser.setUsername("regularuser");
        regularUser.setEmail("user@example.com");
        regularUser.setPassword(passwordEncoder.encode("Password123!"));
        regularUser.setRole(Role.USER);
        regularUser.setEnabled(true);
        regularUser.setBanned(false);
        regularUser = userRepository.save(regularUser);

        // Log in as admin to get token
        SignInRequest signInRequest = new SignInRequest(
                adminUser.getUsername(),
                "AdminPass123!"
        );

        ResponseEntity<AuthResponse> loginResponse = restTemplate.postForEntity(
                "/api/v1/auth/signin",
                signInRequest,
                AuthResponse.class
        );

        adminToken = loginResponse.getBody().getToken();
    }

    @AfterEach
    void tearDown() {
        userRepository.deleteAll();
    }

    @Test
    @DisplayName("Admin should be able to get all users")
    void admin_ShouldGetAllUsers() {
        // Given
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(adminToken);
        HttpEntity<?> requestEntity = new HttpEntity<>(headers);

        // When
        ResponseEntity<List<UserResponse>> response = restTemplate.exchange(
                "/api/v1/admin/users",
                HttpMethod.GET,
                requestEntity,
                new ParameterizedTypeReference<List<UserResponse>>() {}
        );

        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().size()).isGreaterThanOrEqualTo(2);  // At least admin and regular user

        // Verify that both our test users are in the list
        List<String> usernames = response.getBody().stream()
                .map(UserResponse::getUsername)
                .toList();
        assertThat(usernames).contains(adminUser.getUsername(), regularUser.getUsername());
    }

    @Test
    @DisplayName("Admin should be able to update user role")
    void admin_ShouldUpdateUserRole() {
        // Given
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(adminToken);
        HttpEntity<?> requestEntity = new HttpEntity<>(headers);

        String url = UriComponentsBuilder.fromPath("/api/v1/admin/users/{userId}/role")
                .buildAndExpand(regularUser.getId())
                .toUriString() + "?role=ADMIN";

        // When
        ResponseEntity<RoleUpdateResponse> response = restTemplate.exchange(
                url,
                HttpMethod.PUT,
                requestEntity,
                RoleUpdateResponse.class
        );

        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().getRole()).isEqualTo(Role.ADMIN);
        assertThat(response.getBody().getUsername()).isEqualTo(regularUser.getUsername());

        // Verify database was updated
        User updatedUser = userRepository.findById(regularUser.getId()).orElseThrow();
        assertThat(updatedUser.getRole()).isEqualTo(Role.ADMIN);
    }

    @Test
    @DisplayName("Admin should be able to ban a user")
    void admin_ShouldBanUser() {
        // Given
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(adminToken);
        HttpEntity<?> requestEntity = new HttpEntity<>(headers);

        String url = UriComponentsBuilder.fromPath("/api/v1/admin/users/{userId}/ban")
                .queryParam("banned", true)
                .buildAndExpand(regularUser.getId())
                .toUriString();

        // When
        ResponseEntity<BanStatusResponse> response = restTemplate.exchange(
                url,
                HttpMethod.PUT,
                requestEntity,
                BanStatusResponse.class
        );

        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().isBanned()).isTrue();
        assertThat(response.getBody().getUsername()).isEqualTo(regularUser.getUsername());

        // Verify database was updated
        User updatedUser = userRepository.findById(regularUser.getId()).orElseThrow();
        assertThat(updatedUser.isBanned()).isTrue();
    }

    @Test
    @DisplayName("Admin should be able to unban a user")
    void admin_ShouldUnbanUser() {
        // Given
        // First ban the user
        regularUser.setBanned(true);
        userRepository.save(regularUser);

        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(adminToken);
        HttpEntity<?> requestEntity = new HttpEntity<>(headers);

        String url = UriComponentsBuilder.fromPath("/api/v1/admin/users/{userId}/ban")
                .queryParam("banned", false)
                .buildAndExpand(regularUser.getId())
                .toUriString();

        // When
        ResponseEntity<BanStatusResponse> response = restTemplate.exchange(
                url,
                HttpMethod.PUT,
                requestEntity,
                BanStatusResponse.class
        );

        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().isBanned()).isFalse();
        assertThat(response.getBody().getUsername()).isEqualTo(regularUser.getUsername());

        // Verify database was updated
        User updatedUser = userRepository.findById(regularUser.getId()).orElseThrow();
        assertThat(updatedUser.isBanned()).isFalse();
    }

    @Test
    @DisplayName("Regular user should not access admin endpoints")
    void regularUser_ShouldNotAccessAdminEndpoints() {
        // Given
        // Login as regular user
        SignInRequest signInRequest = new SignInRequest(
                regularUser.getUsername(),
                "Password123!"
        );

        ResponseEntity<AuthResponse> loginResponse = restTemplate.postForEntity(
                "/api/v1/auth/signin",
                signInRequest,
                AuthResponse.class
        );

        String regularUserToken = loginResponse.getBody().getToken();

        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(regularUserToken);
        HttpEntity<?> requestEntity = new HttpEntity<>(headers);

        // When
        ResponseEntity<Object> response = restTemplate.exchange(
                "/api/v1/admin/users",
                HttpMethod.GET,
                requestEntity,
                Object.class
        );

        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }
} 