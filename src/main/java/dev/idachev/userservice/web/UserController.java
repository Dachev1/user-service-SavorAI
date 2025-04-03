package dev.idachev.userservice.web;

import dev.idachev.userservice.model.Role;
import dev.idachev.userservice.service.TokenService;
import dev.idachev.userservice.service.UserService;
import dev.idachev.userservice.web.dto.AuthResponse;
import dev.idachev.userservice.web.dto.GenericResponse;
import dev.idachev.userservice.web.dto.UserResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

/**
 * Controller for user management operations
 */
@Slf4j
@RestController
@RequestMapping("/api/v1")
@Tag(name = "User Management", description = "Endpoints for user management")
public class UserController {

    private final UserService userService;
    private final TokenService tokenService;

    @Autowired
    public UserController(UserService userService, TokenService tokenService) {
        this.userService = userService;
        this.tokenService = tokenService;
    }

    @GetMapping("/user/check-username")
    @Operation(summary = "Check username availability")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Username availability checked successfully"),
            @ApiResponse(responseCode = "400", description = "Invalid username format")
    })
    public ResponseEntity<GenericResponse> checkUsernameAvailability(@RequestParam String username) {
        log.info("Checking username availability for: {}", username);

        boolean isAvailable = !userService.existsByUsername(username);
        log.info("Username {} is {}", username, isAvailable ? "available" : "taken");

        return ResponseEntity.ok(GenericResponse.builder()
                .status(200)
                .message(isAvailable ? "Username is available" : "Username is already taken")
                .timestamp(LocalDateTime.now())
                .success(isAvailable)
                .build());
    }

    // ===================== ADMIN ENDPOINTS =====================

    @GetMapping("/admin/users")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Get all users (admin only)", description = "Retrieves information about all users in the system", security = @SecurityRequirement(name = "bearerAuth"))
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Users retrieved successfully"),
            @ApiResponse(responseCode = "403", description = "Forbidden - requires admin role")
    })
    public ResponseEntity<List<UserResponse>> getAllUsers() {
        log.info("Admin request to get all users");
        List<UserResponse> users = userService.getAllUsers();
        return ResponseEntity.ok(users);
    }

    @PutMapping("/admin/users/{userId}/role")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Update user role (admin only)", description = "Changes a user's role in the system", security = @SecurityRequirement(name = "bearerAuth"))
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Role updated successfully"),
            @ApiResponse(responseCode = "404", description = "User not found"),
            @ApiResponse(responseCode = "403", description = "Forbidden - requires admin role")
    })
    public ResponseEntity<GenericResponse> updateUserRole(
            @PathVariable UUID userId,
            @RequestParam Role role,
            @AuthenticationPrincipal UserDetails admin) {
        log.info("Admin {} is updating user {} role to {}", admin.getUsername(), userId, role);

        // Make sure admin is not changing their own role
        if (userService.isCurrentUser(userId)) {
            return ResponseEntity.ok(GenericResponse.builder()
                    .status(400)
                    .message("Admins cannot change their own role")
                    .timestamp(LocalDateTime.now())
                    .success(false)
                    .build());
        }

        // Delegate the entire role update process to the service layer
        GenericResponse response = userService.updateUserRoleWithTokenRefresh(userId, role);
        return ResponseEntity.ok(response);
    }

    @PutMapping("/admin/users/{userId}/ban")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Toggle user ban status (admin only)", description = "Toggles a user's ban status (banned/unbanned)", security = @SecurityRequirement(name = "bearerAuth"))
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "User ban status toggled successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "403", description = "Forbidden - requires admin role"),
            @ApiResponse(responseCode = "404", description = "User not found")
    })
    public ResponseEntity<GenericResponse> toggleUserBan(
            @PathVariable UUID userId,
            @AuthenticationPrincipal UserDetails admin) {
        log.info("Admin {} is toggling ban status for user {}", admin.getUsername(), userId);

        // Prevent an admin from banning themselves
        if (userService.isCurrentUser(userId)) {
            return ResponseEntity.ok(GenericResponse.builder()
                    .status(400)
                    .message("Admins cannot ban themselves")
                    .timestamp(LocalDateTime.now())
                    .success(false)
                    .build());
        }

        GenericResponse response = userService.toggleUserBan(userId);

        // If the user was banned, invalidate their tokens
        if (response.isSuccess() && response.getMessage().contains("banned")) {
            log.info("User {} was banned, invalidating their tokens", userId);
            tokenService.invalidateUserTokens(userId);
        }

        return ResponseEntity.ok(response);
    }

//    @RequestMapping(value = "/admin", method = RequestMethod.OPTIONS)
//    public ResponseEntity<?> options() {
//        return ResponseEntity.ok().build();
//    }
}