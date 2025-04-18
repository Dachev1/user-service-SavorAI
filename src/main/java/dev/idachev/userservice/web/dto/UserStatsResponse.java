package dev.idachev.userservice.web.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * Response DTO for user statistics
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "User statistics information")
public class UserStatsResponse {
    @Schema(description = "Total number of users", example = "1250")
    private long totalUsers;
    
    @Schema(description = "Number of active (non-banned) users", example = "1200")
    private long activeUsers;
    
    @Schema(description = "Number of banned users", example = "50")
    private long bannedUsers;
    
    @Schema(description = "Number of users with verified emails", example = "950")
    private long verifiedUsers;
    
    @Schema(description = "Number of admin users", example = "5")
    private long adminUsers;
    
    @Schema(description = "Timestamp when statistics were generated", example = "2024-03-20T15:30:00")
    private LocalDateTime timestamp;
} 