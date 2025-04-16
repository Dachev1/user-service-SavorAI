package dev.idachev.userservice.web.dto;

import dev.idachev.userservice.model.Role;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Response DTO for user role operations
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RoleUpdateResponse {
    private int status;
    private String message;
    private LocalDateTime timestamp;
    private boolean success;
    private UUID userId;
    private String username;
    private Role role;
    private boolean tokenRefreshed;

    /**
     * Factory method to create a success response
     */
    public static RoleUpdateResponse success(UUID userId, String username, Role role, boolean tokenRefreshed) {
        return RoleUpdateResponse.builder()
                .status(200)
                .message("User role updated successfully" + 
                        (tokenRefreshed ? "" : " (Note: Token refresh failed, user will need to log out and back in)"))
                .timestamp(LocalDateTime.now())
                .success(true)
                .userId(userId)
                .username(username)
                .role(role)
                .tokenRefreshed(tokenRefreshed)
                .build();
    }

    /**
     * Factory method to create an error response
     */
    public static RoleUpdateResponse error(String message) {
        return RoleUpdateResponse.builder()
                .status(400)
                .message(message)
                .timestamp(LocalDateTime.now())
                .success(false)
                .build();
    }
} 