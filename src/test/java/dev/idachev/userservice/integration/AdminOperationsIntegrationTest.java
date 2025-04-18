package dev.idachev.userservice.integration;

import dev.idachev.userservice.model.Role;
import dev.idachev.userservice.model.User;
import dev.idachev.userservice.repository.UserRepository;
import dev.idachev.userservice.service.TokenService;
import dev.idachev.userservice.web.dto.AuthResponse;
import dev.idachev.userservice.web.dto.BanStatusResponse;
import dev.idachev.userservice.web.dto.GenericResponse;
import dev.idachev.userservice.web.dto.RoleUpdateResponse;
import dev.idachev.userservice.web.dto.SignInRequest;
import dev.idachev.userservice.web.dto.UserResponse;
import dev.idachev.userservice.web.dto.UserStatsResponse;
import dev.idachev.userservice.security.UserPrincipal;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.web.util.UriComponentsBuilder;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
class AdminOperationsIntegrationTest {
    private static final Logger logger = LoggerFactory.getLogger(AdminOperationsIntegrationTest.class);
    private static final String DEFAULT_PASSWORD = "Password123!";
    private static final String API_ADMIN_USERS_PATH = "/api/v1/admin/users";
    
    @Autowired
    private TestRestTemplate restTemplate;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;
    
    @Autowired
    private TokenService tokenService;

    private User adminUser;
    private User regularUser;
    private String adminToken;
    private final List<User> testUsers = new ArrayList<>();

    @BeforeEach
    void setUp() {
        // Create an admin user
        adminUser = createUser("adminuser", "admin@example.com", Role.ADMIN, true);
        
        // Create a regular user
        regularUser = createUser("regularuser", "user@example.com", Role.USER, true);
        
        // Generate auth token for admin
        adminToken = tokenService.generateToken(new UserPrincipal(adminUser));
    }

    @AfterEach
    void tearDown() {
        try {
            userRepository.deleteAll();
            testUsers.clear();
        } catch (Exception e) {
            logger.error("Error during test cleanup: {}", e.getMessage());
        }
    }
    
    private User createUser(String username, String email, Role role, boolean enabled) {
        User user = new User();
        user.setUsername(username);
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode(DEFAULT_PASSWORD));
        user.setRole(role);
        user.setEnabled(enabled);
        user = userRepository.save(user);
        testUsers.add(user);
        return user;
    }
    
    private HttpHeaders getAuthHeaders() {
        HttpHeaders headers = new HttpHeaders();
        headers.set(HttpHeaders.AUTHORIZATION, "Bearer " + adminToken);
        headers.setContentType(MediaType.APPLICATION_JSON);
        return headers;
    }

    @Test
    @DisplayName("Should get all users as admin")
    void should_GetAllUsers_AsAdmin() {
        // Given
        HttpHeaders headers = getAuthHeaders();
        HttpEntity<Void> requestEntity = new HttpEntity<>(headers);
        
        // When
        ResponseEntity<List<UserResponse>> response = restTemplate.exchange(
                API_ADMIN_USERS_PATH, 
                HttpMethod.GET, 
                requestEntity, 
                new ParameterizedTypeReference<List<UserResponse>>() {});
        
        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().size()).isGreaterThanOrEqualTo(2); // At least admin and regular user
        
        // Check if the users are in the response
        boolean foundAdmin = false;
        boolean foundRegular = false;
        
        for (UserResponse user : response.getBody()) {
            if (user.getUsername().equals(adminUser.getUsername())) {
                foundAdmin = true;
                assertThat(user.getRole()).isEqualTo("ADMIN");
            }
            else if (user.getUsername().equals(regularUser.getUsername())) {
                foundRegular = true;
                assertThat(user.getRole()).isEqualTo("USER");
            }
        }
        
        assertThat(foundAdmin).isTrue();
        assertThat(foundRegular).isTrue();
    }
    
    @Test
    @DisplayName("Should get user by id as admin")
    void should_GetUserById_AsAdmin() {
        // Given
        HttpHeaders headers = getAuthHeaders();
        HttpEntity<Void> requestEntity = new HttpEntity<>(headers);
        
        // When
        ResponseEntity<UserResponse> response = restTemplate.exchange(
                API_ADMIN_USERS_PATH + "/" + regularUser.getId(), 
                HttpMethod.GET, 
                requestEntity, 
                UserResponse.class);
        
        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().getUsername()).isEqualTo(regularUser.getUsername());
        assertThat(response.getBody().getEmail()).isEqualTo(regularUser.getEmail());
        assertThat(response.getBody().getRole()).isEqualTo("USER");
    }
    
    @Test
    @DisplayName("Should toggle user ban status as admin")
    void should_ToggleUserBanStatus_AsAdmin() {
        // Given
        HttpHeaders headers = getAuthHeaders();
        HttpEntity<Void> requestEntity = new HttpEntity<>(headers);
        
        // Verify user is not banned initially
        assertThat(regularUser.isBanned()).isFalse();
        
        // When - ban user
        ResponseEntity<BanStatusResponse> response = restTemplate.exchange(
                API_ADMIN_USERS_PATH + "/" + regularUser.getId() + "/ban", 
                HttpMethod.PUT, 
                requestEntity, 
                BanStatusResponse.class);
        
        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().isBanned()).isTrue(); // User should be banned now
        
        // Verify user is banned in database
        User updatedUser = userRepository.findById(regularUser.getId()).orElseThrow();
        assertThat(updatedUser.isBanned()).isTrue();
        
        // When - unban user
        response = restTemplate.exchange(
                API_ADMIN_USERS_PATH + "/" + regularUser.getId() + "/ban", 
                HttpMethod.PUT, 
                requestEntity, 
                BanStatusResponse.class);
        
        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().isBanned()).isFalse(); // User should be unbanned now
        
        // Verify user is unbanned in database
        updatedUser = userRepository.findById(regularUser.getId()).orElseThrow();
        assertThat(updatedUser.isBanned()).isFalse();
    }
    
    @Test
    @DisplayName("Should delete user as admin")
    void should_DeleteUser_AsAdmin() {
        // Given
        HttpHeaders headers = getAuthHeaders();
        HttpEntity<Void> requestEntity = new HttpEntity<>(headers);
        
        // When
        ResponseEntity<GenericResponse> response = restTemplate.exchange(
                API_ADMIN_USERS_PATH + "/" + regularUser.getId(), 
                HttpMethod.DELETE, 
                requestEntity, 
                GenericResponse.class);
        
        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().isSuccess()).isTrue();
        assertThat(response.getBody().getMessage()).contains("deleted");
        
        // Verify user was deleted from database
        assertThat(userRepository.findById(regularUser.getId())).isEmpty();
    }
    
    @Test
    @DisplayName("Should get user statistics as admin")
    void should_GetUserStats_AsAdmin() {
        // Given
        HttpHeaders headers = getAuthHeaders();
        HttpEntity<Void> requestEntity = new HttpEntity<>(headers);
        
        // When
        ResponseEntity<UserStatsResponse> response = restTemplate.exchange(
                API_ADMIN_USERS_PATH + "/stats", 
                HttpMethod.GET, 
                requestEntity, 
                UserStatsResponse.class);
        
        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().getTotalUsers()).isGreaterThanOrEqualTo(2); // At least admin and regular user
    }
    
    @Test
    @DisplayName("Should fail to access admin endpoints as regular user")
    void should_FailToAccessAdminEndpoints_AsRegularUser() {
        // Given
        String regularUserToken = tokenService.generateToken(new UserPrincipal(regularUser));
        
        HttpHeaders headers = new HttpHeaders();
        headers.set(HttpHeaders.AUTHORIZATION, "Bearer " + regularUserToken);
        headers.setContentType(MediaType.APPLICATION_JSON);
        
        HttpEntity<Void> requestEntity = new HttpEntity<>(headers);
        
        // When - the regular user tries to access an admin endpoint
        ResponseEntity<String> response = restTemplate.exchange(
                API_ADMIN_USERS_PATH, 
                HttpMethod.GET, 
                requestEntity, 
                String.class);
        
        // Then - in our current security implementation, regular users get 401 UNAUTHORIZED 
        // when trying to access admin endpoints (though 403 FORBIDDEN would be more semantically correct)
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        
        // Additionally, verify the user is actually a non-admin
        assertThat(regularUser.getRole()).isEqualTo(Role.USER);
    }
    
    @Test
    @DisplayName("Should fail to access admin endpoints without authentication")
    void should_FailToAccessAdminEndpoints_WithoutAuthentication() {
        // When - try without auth
        ResponseEntity<String> response = restTemplate.exchange(
                API_ADMIN_USERS_PATH, 
                HttpMethod.GET, 
                HttpEntity.EMPTY, 
                String.class);
        
        // Then - unauthenticated requests get 401 UNAUTHORIZED
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }
    
    @Test
    @DisplayName("Should handle not found user as admin")
    void should_HandleNotFoundUser_AsAdmin() {
        // Given - a non-existent user ID
        UUID nonExistentId = UUID.randomUUID();
        HttpHeaders headers = getAuthHeaders();
        HttpEntity<Void> requestEntity = new HttpEntity<>(headers);
        
        // First verify the user doesn't exist in the database
        assertThat(userRepository.findById(nonExistentId)).isEmpty();
        
        // When - try to access non-existent user
        ResponseEntity<String> response = restTemplate.exchange(
                API_ADMIN_USERS_PATH + "/" + nonExistentId, 
                HttpMethod.GET, 
                requestEntity, 
                String.class);
        
        // Then - just verify we get an error status code (4xx)
        assertThat(response.getStatusCode().is4xxClientError()).isTrue();
    }
} 