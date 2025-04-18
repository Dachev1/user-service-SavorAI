package dev.idachev.userservice.integration;

import dev.idachev.userservice.model.Role;
import dev.idachev.userservice.model.User;
import dev.idachev.userservice.repository.UserRepository;
import dev.idachev.userservice.web.dto.AuthResponse;
import dev.idachev.userservice.web.dto.GenericResponse;
import dev.idachev.userservice.web.dto.ProfileUpdateRequest;
import dev.idachev.userservice.web.dto.SignInRequest;
import dev.idachev.userservice.web.dto.UsernameAvailabilityResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.web.util.UriComponentsBuilder;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
class UserProfileIntegrationTest {

    @Autowired
    private TestRestTemplate restTemplate;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    private User testUser;
    private String authToken;
    
    @BeforeEach
    void setUp() {
        // Create test user
        testUser = new User();
        testUser.setUsername("testuser");
        testUser.setEmail("testuser@example.com");
        testUser.setPassword(passwordEncoder.encode("Password123!"));
        testUser.setRole(Role.USER);
        testUser.setEnabled(true);
        testUser.setBanned(false);
        testUser = userRepository.save(testUser);
        
        // Log in to get auth token
        SignInRequest signInRequest = new SignInRequest(
                testUser.getUsername(),
                "Password123!"
        );
        
        ResponseEntity<AuthResponse> loginResponse = restTemplate.postForEntity(
                "/api/v1/auth/signin",
                signInRequest,
                AuthResponse.class
        );
        
        authToken = loginResponse.getBody().getToken();
    }
    
    @AfterEach
    void tearDown() {
        userRepository.deleteAll();
    }

    @Test
    @DisplayName("Should check username availability correctly")
    void should_CheckUsernameAvailability_Correctly() {
        // Test for taken username
        String takenUrl = UriComponentsBuilder.fromPath("/api/v1/user/check-username")
                .queryParam("username", testUser.getUsername())
                .toUriString();
        ResponseEntity<UsernameAvailabilityResponse> takenResponse = restTemplate.getForEntity(
                takenUrl, 
                UsernameAvailabilityResponse.class
        );
        
        assertThat(takenResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(takenResponse.getBody()).isNotNull();
        assertThat(takenResponse.getBody().isAvailable()).isFalse();
        
        // Test for available username
        String availableUrl = UriComponentsBuilder.fromPath("/api/v1/user/check-username")
                .queryParam("username", "newusername123")
                .toUriString();
        ResponseEntity<UsernameAvailabilityResponse> availableResponse = restTemplate.getForEntity(
                availableUrl, 
                UsernameAvailabilityResponse.class
        );
        
        assertThat(availableResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(availableResponse.getBody()).isNotNull();
        assertThat(availableResponse.getBody().isAvailable()).isTrue();
    }
    
    @Test
    @DisplayName("Should update username successfully")
    void should_UpdateUsername_Successfully() {
        // Given
        ProfileUpdateRequest updateRequest = new ProfileUpdateRequest(
                "newusername",
                "Password123!"
        );
        
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(authToken);
        HttpEntity<ProfileUpdateRequest> requestEntity = new HttpEntity<>(updateRequest, headers);
        
        // When
        ResponseEntity<GenericResponse> response = restTemplate.exchange(
                "/api/v1/user/update-username", 
                HttpMethod.POST, 
                requestEntity, 
                GenericResponse.class
        );
        
        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().isSuccess()).isTrue();
        
        // Verify the username was updated in database
        User updatedUser = userRepository.findById(testUser.getId()).orElseThrow();
        assertThat(updatedUser.getUsername()).isEqualTo("newusername");
    }
    
    @Test
    @DisplayName("Should reject username update with incorrect password")
    void should_RejectUsernameUpdate_WithIncorrectPassword() {
        // Given
        ProfileUpdateRequest updateRequest = new ProfileUpdateRequest(
                "newusername",
                "WrongPassword!"
        );
        
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(authToken);
        HttpEntity<ProfileUpdateRequest> requestEntity = new HttpEntity<>(updateRequest, headers);
        
        // When
        ResponseEntity<GenericResponse> response = restTemplate.exchange(
                "/api/v1/user/update-username", 
                HttpMethod.POST, 
                requestEntity, 
                GenericResponse.class
        );
        
        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().isSuccess()).isFalse();
        
        // Verify the username was not updated
        User unchangedUser = userRepository.findById(testUser.getId()).orElseThrow();
        assertThat(unchangedUser.getUsername()).isEqualTo(testUser.getUsername());
    }
    
    @Test
    @DisplayName("Should reject username update with taken username")
    void should_RejectUsernameUpdate_WithTakenUsername() {
        // Given - create another user with the username we'll try to take
        User anotherUser = new User();
        anotherUser.setUsername("takenname");
        anotherUser.setEmail("another@example.com");
        anotherUser.setPassword(passwordEncoder.encode("Password123!"));
        anotherUser.setRole(Role.USER);
        anotherUser.setEnabled(true);
        anotherUser.setBanned(false);
        userRepository.save(anotherUser);
        
        ProfileUpdateRequest updateRequest = new ProfileUpdateRequest(
                "takenname",
                "Password123!"
        );
        
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(authToken);
        HttpEntity<ProfileUpdateRequest> requestEntity = new HttpEntity<>(updateRequest, headers);
        
        // When
        ResponseEntity<GenericResponse> response = restTemplate.exchange(
                "/api/v1/user/update-username", 
                HttpMethod.POST, 
                requestEntity, 
                GenericResponse.class
        );
        
        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().isSuccess()).isFalse();
        assertThat(response.getBody().getMessage()).contains("Username already exists");
        
        // Verify the username was not updated
        User unchangedUser = userRepository.findById(testUser.getId()).orElseThrow();
        assertThat(unchangedUser.getUsername()).isEqualTo(testUser.getUsername());
    }
} 