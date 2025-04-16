package dev.idachev.userservice.web.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Response DTO for user ban operations
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class BanStatusResponse {
    private int status;
    private String message;
    private LocalDateTime timestamp;
    private boolean success;
    private UUID userId;
    private String username;
    private boolean banned;

    /**
     * Factory method to create a success response
     */
    public static BanStatusResponse success(UUID userId, String username, boolean banned, String message) {
        return BanStatusResponse.builder()
                .status(200)
                .message(message)
                .timestamp(LocalDateTime.now())
                .success(true)
                .userId(userId)
                .username(username)
                .banned(banned)
                .build();
    }

    /**
     * Factory method to create an error response
     */
    public static BanStatusResponse error(String message) {
        return BanStatusResponse.builder()
                .status(400)
                .message(message)
                .timestamp(LocalDateTime.now())
                .success(false)
                .build();
    }
} 