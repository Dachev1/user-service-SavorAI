package dev.idachev.userservice.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.idachev.userservice.config.TestSecurityConfig;
import dev.idachev.userservice.exception.ResourceNotFoundException;
import dev.idachev.userservice.service.ProfileService;
import dev.idachev.userservice.web.dto.ProfileUpdateRequest;
import dev.idachev.userservice.web.dto.UserResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.security.Principal;
import java.time.LocalDateTime;
import java.util.Collections;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(controllers = ProfileController.class)
@AutoConfigureMockMvc(addFilters = false)
@Import(TestSecurityConfig.class)
public class ProfileControllerApiTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockitoBean
    private ProfileService profileService;

    private UserResponse userResponse;
    private UserResponse otherUserResponse;
    private ProfileUpdateRequest profileUpdateRequest;
    private String currentUsername = "testuser";

    @BeforeEach
    public void setup() {
        // Set up test data
        userResponse = new UserResponse();
        userResponse.setId(UUID.randomUUID());
        userResponse.setUsername(currentUsername);
        userResponse.setEmail("test@example.com");
        userResponse.setRole("USER");
        userResponse.setVerified(true);
        userResponse.setCreatedOn(LocalDateTime.now());

        otherUserResponse = new UserResponse();
        otherUserResponse.setId(UUID.randomUUID());
        otherUserResponse.setUsername("otheruser");
        otherUserResponse.setEmail("other@example.com");
        otherUserResponse.setRole("USER");
        otherUserResponse.setVerified(true);
        otherUserResponse.setCreatedOn(LocalDateTime.now());

        profileUpdateRequest = new ProfileUpdateRequest();
        profileUpdateRequest.setUsername("newusername");
    }

    @Nested
    @DisplayName("Primary Endpoints")
    class PrimaryEndpoints {
        @Test
        @DisplayName("GET /api/v1/profile - Returns current user profile")
        void getProfile_ReturnsCurrentUserProfile() throws Exception {
            when(profileService.getCurrentUserInfo()).thenReturn(userResponse);
    
            mockMvc.perform(get("/api/v1/profile")
                            .contentType(MediaType.APPLICATION_JSON))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.username").value(userResponse.getUsername()))
                    .andExpect(jsonPath("$.id").value(userResponse.getId().toString()));
    
            verify(profileService).getCurrentUserInfo();
        }
    
        @Test
        @DisplayName("GET /api/v1/profile - When not authenticated returns 401")
        void getProfile_WhenNotAuthenticated_ReturnsUnauthorized() throws Exception {
            when(profileService.getCurrentUserInfo())
                    .thenThrow(new dev.idachev.userservice.exception.AuthenticationException("User not authenticated"));
    
            mockMvc.perform(get("/api/v1/profile")
                            .contentType(MediaType.APPLICATION_JSON))
                    .andExpect(status().isUnauthorized());
    
            verify(profileService).getCurrentUserInfo();
        }
    
        @Test
        @DisplayName("GET /api/v1/profile/{username} - Returns user profile by username")
        void getProfileByUsername_ReturnsUserProfile() throws Exception {
            String username = "otheruser";
            when(profileService.getUserInfo(username)).thenReturn(otherUserResponse);
    
            mockMvc.perform(get("/api/v1/profile/{username}", username)
                            .contentType(MediaType.APPLICATION_JSON))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.username").value(otherUserResponse.getUsername()))
                    .andExpect(jsonPath("$.id").value(otherUserResponse.getId().toString()));
    
            verify(profileService).getUserInfo(username);
        }
    
        @Test
        @DisplayName("GET /api/v1/profile/{username} - When user not found returns 404")
        void getProfileByUsername_WhenUserNotFound_ReturnsNotFound() throws Exception {
            String username = "nonexistent";
            when(profileService.getUserInfo(username))
                    .thenThrow(new ResourceNotFoundException("User not found with username: " + username));
    
            mockMvc.perform(get("/api/v1/profile/{username}", username)
                            .contentType(MediaType.APPLICATION_JSON))
                    .andExpect(status().isNotFound());
    
            verify(profileService).getUserInfo(username);
        }
    
        @Test
        @DisplayName("PUT /api/v1/profile - Updates user profile")
        void updateProfile_UpdatesUserProfile() throws Exception {
            when(profileService.updateProfile(eq(currentUsername), any(ProfileUpdateRequest.class)))
                    .thenReturn(userResponse);
    
            mockMvc.perform(put("/api/v1/profile")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(profileUpdateRequest))
                            .principal(createPrincipal(currentUsername)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.username").value(userResponse.getUsername()))
                    .andExpect(jsonPath("$.id").value(userResponse.getId().toString()));
    
            verify(profileService).updateProfile(eq(currentUsername), any(ProfileUpdateRequest.class));
        }
    }

    @Nested
    @DisplayName("Compatibility Endpoints")
    class CompatibilityEndpoints {
        @ParameterizedTest
        @ValueSource(strings = {
            "/api/v1/profile/profile", 
            "/api/v1/profile/user/current-user",
            "/api/v1/profile/user/profile",
            "/api/v1/profile/auth/profile"
        })
        @DisplayName("GET compatibility endpoints - Return current user profile")
        void compatibilityEndpoints_ReturnCurrentUserProfile(String endpoint) throws Exception {
            when(profileService.getCurrentUserInfo()).thenReturn(userResponse);
    
            mockMvc.perform(get(endpoint)
                            .contentType(MediaType.APPLICATION_JSON))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.username").value(userResponse.getUsername()))
                    .andExpect(jsonPath("$.id").value(userResponse.getId().toString()));
    
            verify(profileService).getCurrentUserInfo();
        }
    
        @ParameterizedTest
        @ValueSource(strings = {
            "/api/v1/profile/profile/{username}",
            "/api/v1/profile/user/profile/{username}"
        })
        @DisplayName("GET compatibility username endpoints - Return user profile by username")
        void compatibilityUsernameEndpoints_ReturnUserProfile(String endpointTemplate) throws Exception {
            String username = "otheruser";
            when(profileService.getUserInfo(username)).thenReturn(otherUserResponse);
    
            String endpoint = endpointTemplate.replace("{username}", username);
            mockMvc.perform(get(endpoint)
                            .contentType(MediaType.APPLICATION_JSON))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.username").value(otherUserResponse.getUsername()))
                    .andExpect(jsonPath("$.id").value(otherUserResponse.getId().toString()));
    
            verify(profileService).getUserInfo(username);
        }
    
        @Test
        @DisplayName("PUT /api/v1/profile/profile - Updates user profile (compatibility)")
        void updateProfileCompat_UpdatesUserProfile() throws Exception {
            when(profileService.updateProfile(eq(currentUsername), any(ProfileUpdateRequest.class)))
                    .thenReturn(userResponse);
    
            mockMvc.perform(put("/api/v1/profile/profile")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(profileUpdateRequest))
                            .principal(createPrincipal(currentUsername)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.username").value(userResponse.getUsername()))
                    .andExpect(jsonPath("$.id").value(userResponse.getId().toString()));
    
            verify(profileService).updateProfile(eq(currentUsername), any(ProfileUpdateRequest.class));
        }
    }
    
    private Principal createPrincipal(String username) {
        return new UsernamePasswordAuthenticationToken(username, "password", Collections.emptyList());
    }
} 