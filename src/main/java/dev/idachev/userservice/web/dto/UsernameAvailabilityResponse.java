package dev.idachev.userservice.web.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * Response DTO for username availability check
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UsernameAvailabilityResponse {
    private int status;
    private String message;
    private LocalDateTime timestamp;
    private boolean success;
    private String username;
    private boolean available;

    /**
     * Factory method to create an availability response
     */
    public static UsernameAvailabilityResponse of(String username, boolean available) {
        return UsernameAvailabilityResponse.builder()
                .status(200)
                .message(available ? "Username is available" : "Username is already taken")
                .timestamp(LocalDateTime.now())
                .success(true)
                .username(username)
                .available(available)
                .build();
    }
} 