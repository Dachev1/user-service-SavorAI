package dev.idachev.userservice.web.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * DTO representing the basic status (username, enabled, banned) of a user.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserStatusResponse {
    private String username;
    private boolean enabled;
    private boolean banned;
} 