package dev.idachev.recipeservice.user.client;

import dev.idachev.recipeservice.user.dto.UserDTO;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestHeader;

import java.util.UUID;

/**
 * Client interface for communicating with the user service.
 */
@FeignClient(name = "user-service", url = "${app.services.user-service.url}")
public interface UserClient {
    /**
     * Get user information by ID.
     *
     * @param token JWT token for authentication
     * @param userId User ID to retrieve
     * @return User data
     */
    @GetMapping("/api/v1/user/{userId}")
    ResponseEntity<UserDTO> getUserById(
            @RequestHeader("Authorization") String token,
            @PathVariable("userId") UUID userId);

    /**
     * Get current user information based on the JWT token.
     *
     * @param token JWT token for authentication
     * @return Current user data
     */
    @GetMapping("/api/v1/user/current-user")
    ResponseEntity<UserDTO> getCurrentUser(
            @RequestHeader("Authorization") String token);
} 