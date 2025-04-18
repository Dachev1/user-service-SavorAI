package dev.idachev.userservice.web;

import dev.idachev.userservice.model.Role;
import dev.idachev.userservice.model.User;
import dev.idachev.userservice.service.UserService;
import dev.idachev.userservice.util.ResponseBuilder;
import dev.idachev.userservice.web.dto.*;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

/**
 * Controller for user management operations (Admin focused)
 */
@RestController
@RequestMapping("/api/v1")
@Tag(name = "User Management", description = "Endpoints for viewing and managing users (Admin access generally required)")
@Validated
@Slf4j
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @GetMapping("/users/check-username")
    @Operation(summary = "Check username availability", description = "Checks if a username is available for registration.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Username availability checked",
                    content = @Content(schema = @Schema(implementation = UsernameAvailabilityResponse.class)))
    })
    public ResponseEntity<UsernameAvailabilityResponse> checkUsernameAvailability(@RequestParam String username) {
        return ResponseEntity.ok(userService.checkUsernameAvailability(username));
    }

    // ===================== ADMIN ENDPOINTS =====================

    @GetMapping("/admin/users")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(
        summary = "Get all users (Admin only)", 
        description = "Retrieves a list of all users in the system.", 
        security = @SecurityRequirement(name = "bearerAuth")
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Users retrieved successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "403", description = "Forbidden")
    })
    public ResponseEntity<List<UserResponse>> getAllUsersAdmin() {
        return ResponseEntity.ok(userService.getAllUsers());
    }

    @PutMapping("/admin/users/{userId}/role")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(
        summary = "Update user role (Admin only)", 
        description = "Changes a specific user's role. Invalidates user's tokens.", 
        security = @SecurityRequirement(name = "bearerAuth")
    )
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "User role updated successfully",
                content = @Content(schema = @Schema(implementation = RoleUpdateResponse.class))),
        @ApiResponse(responseCode = "400", description = "Invalid role specified"),
        @ApiResponse(responseCode = "401", description = "Unauthorized"),
        @ApiResponse(responseCode = "403", description = "Forbidden (e.g., admin changing own role)"),
        @ApiResponse(responseCode = "404", description = "User not found")
    })
    public ResponseEntity<RoleUpdateResponse> updateUserRoleAdmin(
            @PathVariable UUID userId,
            @RequestParam Role role) {
        log.info("Admin request to update role for user {} to {}", userId, role);
        User updatedUser = userService.updateUserRole(userId, role);
        boolean tokenInvalidationSucceeded = true;
        RoleUpdateResponse response = RoleUpdateResponse.success(
                updatedUser.getId(),
                updatedUser.getUsername(),
                updatedUser.getRole(),
                tokenInvalidationSucceeded 
        );
        return ResponseEntity.ok(response);
    }

    @PutMapping("/admin/users/{userId}/ban")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(
        summary = "Toggle user ban status (Admin only)", 
        description = "Toggles a user's ban status (banned/unbanned). Invalidates tokens if user is banned.", 
        security = @SecurityRequirement(name = "bearerAuth")
    )
     @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "User ban status toggled successfully",
                content = @Content(schema = @Schema(implementation = BanStatusResponse.class))),
        @ApiResponse(responseCode = "401", description = "Unauthorized"),
        @ApiResponse(responseCode = "403", description = "Forbidden (e.g., admin banning self)"),
        @ApiResponse(responseCode = "404", description = "User not found")
    })
    public ResponseEntity<BanStatusResponse> toggleUserBanAdmin(@PathVariable UUID userId) {
        log.info("Admin request to toggle ban status for user {}", userId);
        User updatedUser = userService.toggleUserBan(userId);
        String message = updatedUser.isBanned() ? "User banned successfully" : "User unbanned successfully";
        BanStatusResponse response = BanStatusResponse.success(
            updatedUser.getId(), 
            updatedUser.getUsername(), 
            updatedUser.isBanned(),
            message
        );
        return ResponseEntity.ok(response);
    }

    @GetMapping("/admin/users/{userId}")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(
        summary = "Get user by ID (Admin only)",
        description = "Retrieves detailed information about a specific user by ID.",
        security = @SecurityRequirement(name = "bearerAuth")
    )
     @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "User found successfully" ),
        @ApiResponse(responseCode = "401", description = "Unauthorized"),
        @ApiResponse(responseCode = "403", description = "Forbidden"),
        @ApiResponse(responseCode = "404", description = "User not found")
    })
    public ResponseEntity<UserResponse> getUserByIdAdmin(@PathVariable UUID userId) {
        return ResponseEntity.ok(userService.getUserById(userId));
    }

    @DeleteMapping("/admin/users/{userId}")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(
        summary = "Delete user (Admin only)",
        description = "Permanently deletes a user from the system.",
        security = @SecurityRequirement(name = "bearerAuth")
    )
     @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "User deleted successfully",
                content = @Content(schema = @Schema(implementation = GenericResponse.class))),
        @ApiResponse(responseCode = "401", description = "Unauthorized"),
        @ApiResponse(responseCode = "403", description = "Forbidden (e.g., admin deleting self)"),
        @ApiResponse(responseCode = "404", description = "User not found")
    })
    public ResponseEntity<GenericResponse> deleteUserAdmin(@PathVariable UUID userId) {
        log.warn("Admin request to DELETE user with ID: {}", userId);
        userService.deleteUser(userId);
        return ResponseEntity.ok(ResponseBuilder.success("User successfully deleted"));
    }

    @GetMapping("/admin/users/stats")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(
        summary = "Get user statistics (Admin only)",
        description = "Retrieves aggregated statistics about users.",
        security = @SecurityRequirement(name = "bearerAuth")
    )
     @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Statistics retrieved successfully"),
        @ApiResponse(responseCode = "401", description = "Unauthorized"),
        @ApiResponse(responseCode = "403", description = "Forbidden")
    })
    public ResponseEntity<UserStatsResponse> getUserStatsAdmin() {
        return ResponseEntity.ok(userService.getUserStats());
    }
}