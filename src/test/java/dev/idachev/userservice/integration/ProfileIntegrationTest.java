package dev.idachev.userservice.integration;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.idachev.userservice.model.Role;
import dev.idachev.userservice.model.User;
import dev.idachev.userservice.repository.UserRepository;
import dev.idachev.userservice.security.JwtAuthenticationFilter;
import dev.idachev.userservice.security.UserPrincipal;
import dev.idachev.userservice.service.TokenService;
import dev.idachev.userservice.web.dto.GenericResponse;
import dev.idachev.userservice.web.dto.PasswordChangeRequest;
import dev.idachev.userservice.web.dto.ProfileUpdateRequest;
import dev.idachev.userservice.web.dto.UserResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
class ProfileIntegrationTest {
    private static final Logger logger = LoggerFactory.getLogger(ProfileIntegrationTest.class);
    private static final String DEFAULT_PASSWORD = "Password123!";
    private static final String API_PROFILE_PATH = "/api/v1/profile";
    
    @Autowired
    private TestRestTemplate restTemplate;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;
    
    @Autowired
    private TokenService tokenService;
    
    @Autowired
    private ObjectMapper objectMapper;

    private User testUser;
    private String authToken;
    private final List<User> testUsers = new ArrayList<>();

    @BeforeEach
    void setUp() {
        // Create a test user
        testUser = createUser("profiletest", "profiletest@example.com", true);
        
        // Generate auth token for the test user
        authToken = tokenService.generateToken(new UserPrincipal(testUser));
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
    
    private User createUser(String username, String email, boolean enabled) {
        User user = new User();
        user.setUsername(username);
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode(DEFAULT_PASSWORD));
        user.setRole(Role.USER);
        user.setEnabled(enabled);
        user = userRepository.save(user);
        testUsers.add(user);
        return user;
    }
    
    private HttpHeaders getAuthHeaders() {
        HttpHeaders headers = new HttpHeaders();
        headers.set(HttpHeaders.AUTHORIZATION, "Bearer " + authToken);
        headers.setContentType(MediaType.APPLICATION_JSON);
        return headers;
    }

    @Test
    @DisplayName("Should get user profile successfully")
    void should_GetUserProfile_Successfully() {
        // Given
        HttpHeaders headers = getAuthHeaders();
        HttpEntity<Void> requestEntity = new HttpEntity<>(headers);
        
        // When
        ResponseEntity<UserResponse> response = restTemplate.exchange(
                API_PROFILE_PATH, HttpMethod.GET, requestEntity, UserResponse.class);
        
        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().getUsername()).isEqualTo(testUser.getUsername());
        assertThat(response.getBody().getEmail()).isEqualTo(testUser.getEmail());
    }
    
    @Test
    @DisplayName("Should update profile successfully")
    void should_UpdateProfile_Successfully() {
        // Given
        ProfileUpdateRequest updateRequest = new ProfileUpdateRequest();
        updateRequest.setUsername("updatedUsername");
        updateRequest.setCurrentPassword(DEFAULT_PASSWORD);
        
        HttpHeaders headers = getAuthHeaders();
        HttpEntity<ProfileUpdateRequest> requestEntity = new HttpEntity<>(updateRequest, headers);
        
        // When
        ResponseEntity<UserResponse> response = restTemplate.exchange(
                API_PROFILE_PATH, HttpMethod.PUT, requestEntity, UserResponse.class);
        
        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().getUsername()).isEqualTo(updateRequest.getUsername());
        
        // Verify user was updated in database
        User updatedUser = userRepository.findById(testUser.getId()).orElseThrow();
        assertThat(updatedUser.getUsername()).isEqualTo(updateRequest.getUsername());
    }
    
    @Test
    @DisplayName("Should handle password change")
    void should_HandlePasswordChange_Successfully() {
        // Given
        PasswordChangeRequest passwordRequest = new PasswordChangeRequest();
        passwordRequest.setCurrentPassword(DEFAULT_PASSWORD);
        passwordRequest.setNewPassword("NewPassword123!");
        passwordRequest.setConfirmPassword("NewPassword123!");
        
        HttpHeaders headers = getAuthHeaders();
        HttpEntity<PasswordChangeRequest> requestEntity = new HttpEntity<>(passwordRequest, headers);
        
        // When
        ResponseEntity<GenericResponse> response = restTemplate.exchange(
                API_PROFILE_PATH + "/password", HttpMethod.PUT, requestEntity, GenericResponse.class);
        
        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
    }
    
    @Test
    @DisplayName("Should reject password change with incorrect current password")
    void should_RejectPasswordChange_WithIncorrectCurrentPassword() {
        // Given
        PasswordChangeRequest passwordRequest = new PasswordChangeRequest();
        passwordRequest.setCurrentPassword("WrongPassword123!");
        passwordRequest.setNewPassword("NewPassword123!");
        passwordRequest.setConfirmPassword("NewPassword123!");
        
        HttpHeaders headers = getAuthHeaders();
        HttpEntity<PasswordChangeRequest> requestEntity = new HttpEntity<>(passwordRequest, headers);
        
        // When
        ResponseEntity<GenericResponse> response = restTemplate.exchange(
                API_PROFILE_PATH + "/password", HttpMethod.PUT, requestEntity, GenericResponse.class);
        
        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }
    
    @Test
    @DisplayName("Should reject password change when passwords don't match")
    void should_RejectPasswordChange_WhenPasswordsDontMatch() {
        // Given
        PasswordChangeRequest passwordRequest = new PasswordChangeRequest();
        passwordRequest.setCurrentPassword(DEFAULT_PASSWORD);
        passwordRequest.setNewPassword("NewPassword123!");
        passwordRequest.setConfirmPassword("DifferentPassword123!");
        
        HttpHeaders headers = getAuthHeaders();
        HttpEntity<PasswordChangeRequest> requestEntity = new HttpEntity<>(passwordRequest, headers);
        
        // When
        ResponseEntity<GenericResponse> response = restTemplate.exchange(
                API_PROFILE_PATH + "/password", HttpMethod.PUT, requestEntity, GenericResponse.class);
        
        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }
    
    @Test
    @DisplayName("Should return unauthorized for profile access without authentication")
    void should_ReturnUnauthorized_ForProfileAccessWithoutAuthentication() {
        // Given - no authentication headers
        HttpEntity<Void> requestEntity = new HttpEntity<>(new HttpHeaders());
        
        // When
        ResponseEntity<UserResponse> response = restTemplate.exchange(
                API_PROFILE_PATH, HttpMethod.GET, requestEntity, UserResponse.class);
        
        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }
    
    @Test
    @DisplayName("Should delete user account successfully")
    void should_DeleteUserAccount_Successfully() {
        // Given
        HttpHeaders headers = getAuthHeaders();
        HttpEntity<Void> requestEntity = new HttpEntity<>(headers);
        
        // When
        ResponseEntity<GenericResponse> response = restTemplate.exchange(
                API_PROFILE_PATH, HttpMethod.DELETE, requestEntity, GenericResponse.class);
        
        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().isSuccess()).isTrue();
        assertThat(response.getBody().getMessage()).contains("deleted");
        
        // Verify user was deleted from database
        assertThat(userRepository.findById(testUser.getId())).isEmpty();
    }
} 