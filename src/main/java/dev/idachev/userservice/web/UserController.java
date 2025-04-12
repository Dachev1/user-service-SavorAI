package dev.idachev.userservice.web;

import dev.idachev.userservice.model.Role;
import dev.idachev.userservice.service.TokenService;
import dev.idachev.userservice.service.UserService;
import dev.idachev.userservice.web.dto.GenericResponse;
import dev.idachev.userservice.web.dto.UserResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

/**
 * Controller for user management operations
 */
@RestController
@RequestMapping("/api/v1")
@Tag(name = "User Management", description = "Endpoints for user management")
@Validated
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;
    private final TokenService tokenService;

    @GetMapping("/user/check-username")
    @Operation(summary = "Check username availability")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Username availability checked successfully"),
            @ApiResponse(responseCode = "400", description = "Invalid username format")
    })
    public ResponseEntity<GenericResponse> checkUsernameAvailability(@RequestParam String username) {
        return ResponseEntity.ok(userService.checkUsernameAvailability(username));
    }

    // ===================== ADMIN ENDPOINTS =====================

    @GetMapping("/admin/users")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(
        summary = "Get all users (admin only)", 
        description = "Retrieves information about all users in the system", 
        security = @SecurityRequirement(name = "bearerAuth")
    )
    public ResponseEntity<List<UserResponse>> getAllUsers() {
        return ResponseEntity.ok(userService.getAllUsers());
    }

    @PutMapping("/admin/users/{userId}/role")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(
        summary = "Update user role (admin only)", 
        description = "Changes a user's role in the system", 
        security = @SecurityRequirement(name = "bearerAuth")
    )
    public ResponseEntity<GenericResponse> updateUserRole(
            @PathVariable UUID userId,
            @RequestParam Role role) {
        // Check if admin is trying to change their own role
        if (userService.isCurrentUser(userId)) {
            return ResponseEntity.badRequest().body(
                GenericResponse.builder()
                    .status(400)
                    .message("Admins cannot change their own role")
                    .timestamp(LocalDateTime.now())
                    .success(false)
                    .build()
            );
        }
        
        return ResponseEntity.ok(userService.updateUserRoleWithTokenRefresh(userId, role));
    }

    @PutMapping("/admin/users/{userId}/ban")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(
        summary = "Toggle user ban status (admin only)", 
        description = "Toggles a user's ban status (banned/unbanned)", 
        security = @SecurityRequirement(name = "bearerAuth")
    )
    public ResponseEntity<GenericResponse> toggleUserBan(@PathVariable UUID userId) {
        // Check if admin is trying to ban themselves
        if (userService.isCurrentUser(userId)) {
            return ResponseEntity.badRequest().body(
                GenericResponse.builder()
                    .status(400)
                    .message("Admins cannot ban themselves")
                    .timestamp(LocalDateTime.now())
                    .success(false)
                    .build()
            );
        }
        
        GenericResponse response = userService.toggleUserBan(userId);
        
        if (response.isSuccess() && response.getMessage().contains("banned")) {
            tokenService.invalidateUserTokens(userId);
        }
        
        return ResponseEntity.ok(response);
    }
}