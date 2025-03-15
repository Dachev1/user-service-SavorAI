package dev.idachev.recipeservice.user.service;

import dev.idachev.recipeservice.exception.FeignClientException;
import dev.idachev.recipeservice.exception.UnauthorizedException;
import dev.idachev.recipeservice.user.client.UserClient;
import dev.idachev.recipeservice.user.dto.UserDTO;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
@Slf4j
public class UserService {

    private final UserClient userClient;

    @Autowired
    public UserService(UserClient userClient) {
        this.userClient = userClient;
    }

    /**
     * Get current user information based on the JWT token.
     *
     * @param token JWT token for authentication
     * @return Current user data
     * @throws UnauthorizedException if token is invalid
     * @throws FeignClientException  if communication with user-service fails
     */
    public UserDTO getCurrentUser(String token) {

        try {
            ResponseEntity<UserDTO> response = userClient.getCurrentUser(token);

            if (response.getBody() == null) {
                throw new UnauthorizedException("Invalid authentication token");
            }

            return response.getBody();
        } catch (FeignClientException e) {

            log.error("Error from user-service: {}", e.getMessage());
            throw e;
        } catch (Exception e) {

            log.error("Error authenticating user: {}", e.getMessage());
            throw new UnauthorizedException("Authentication failed: " + e.getMessage());
        }
    }

    /**
     * Generate a consistent UUID from a username.
     *
     * @param username The username to convert to UUID
     * @return A UUID deterministically generated from the username
     */
    public UUID getUserIdFromUsername(String username) {

        if (username == null || username.isEmpty()) {
            throw new IllegalArgumentException("Username cannot be null or empty");
        }

        return UUID.nameUUIDFromBytes(username.getBytes());
    }
} 