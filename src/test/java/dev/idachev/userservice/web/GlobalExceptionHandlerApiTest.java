package dev.idachev.userservice.web;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class GlobalExceptionHandlerApiTest {

    private MockMvc mockMvc;

    @BeforeEach
    void setup() {
        // Create a standalone MockMvc instance with our test controller and the exception handler
        mockMvc = MockMvcBuilders.standaloneSetup(new TestController())
                .setControllerAdvice(new GlobalExceptionHandler())
                .build();
    }

    @Test
    void handleNotFoundExceptions_ReturnsNotFoundStatus() throws Exception {
        // When & Then
        mockMvc.perform(get("/test/not-found")
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.status").value(404))
                .andExpect(jsonPath("$.message").value("Resource not found"))
                .andExpect(jsonPath("$.timestamp").exists());
    }

    @Test
    void handleAuthErrors_ReturnsUnauthorizedStatus() throws Exception {
        // When & Then
        mockMvc.perform(get("/test/bad-credentials")
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.status").value(401))
                .andExpect(jsonPath("$.message").value("Invalid credentials"))
                .andExpect(jsonPath("$.timestamp").exists());
    }

    @Test
    void handleAlreadyLoggedIn_ReturnsBadRequestStatus() throws Exception {
        // When & Then
        mockMvc.perform(get("/test/already-logged-in")
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.message", containsString("already logged in")))
                .andExpect(jsonPath("$.timestamp").exists());
    }

    @Test
    void handleDuplicateUserException_ReturnsConflictStatus() throws Exception {
        // When & Then
        mockMvc.perform(get("/test/duplicate-user")
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.status").value(409))
                .andExpect(jsonPath("$.message").value("User already exists"))
                .andExpect(jsonPath("$.timestamp").exists());
    }

    @Test
    void handleBadRequestExceptions_ReturnsBadRequestStatus() throws Exception {
        // When & Then
        mockMvc.perform(get("/test/bad-request")
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.message").value("Invalid request parameters"))
                .andExpect(jsonPath("$.timestamp").exists());
    }

    @Test
    void handleGenericException_ReturnsInternalServerErrorStatus() throws Exception {
        // When & Then
        mockMvc.perform(get("/test/server-error")
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.status").value(500))
                .andExpect(jsonPath("$.message").exists())
                .andExpect(jsonPath("$.timestamp").exists());
    }
} 