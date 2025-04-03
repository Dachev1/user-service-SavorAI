package dev.idachev.userservice.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.idachev.userservice.config.JwtConfig;
import dev.idachev.userservice.model.Role;
import dev.idachev.userservice.service.AuthenticationService;
import dev.idachev.userservice.service.UserService;
import dev.idachev.userservice.web.dto.*;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test") // Ensure test profile is active
public class UserControllerApiTest {

    @MockitoBean
    private UserService userService;

    // AuthenticationService is used by AuthController, keep it mocked if needed for other tests
    @MockitoBean
    private AuthenticationService authenticationService;

    @MockitoBean
    private JwtConfig jwtConfig;

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    // Keep tests related to UserController endpoints (e.g., /api/v1/user/check-username)
    @Test
    void checkUsernameAvailability_WhenAvailable_ReturnsTrue() throws Exception {
        // Given
        String username = "availableUser";
        when(userService.existsByUsername(username)).thenReturn(false);

        // When
        MockHttpServletRequestBuilder request = get("/api/v1/user/check-username")
                .param("username", username)
                .with(csrf());

        // Then
        mockMvc.perform(request)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));
    }

    @Test
    void checkUsernameAvailability_WhenTaken_ReturnsFalse() throws Exception {
        // Given
        String username = "takenUser";
        when(userService.existsByUsername(username)).thenReturn(true);

        // When
        MockHttpServletRequestBuilder request = get("/api/v1/user/check-username")
                .param("username", username)
                .with(csrf());

        // Then
        mockMvc.perform(request)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(false));
    }

    // Remove tests for endpoints moved to AdminController
    // - getAllUsers test removed
    // - setUserRole test removed
} 