package dev.idachev.userservice.web;

import dev.idachev.userservice.exception.ResourceNotFoundException;
import dev.idachev.userservice.model.Role;
import dev.idachev.userservice.service.AuthenticationService;
import dev.idachev.userservice.service.ProfileService;
import dev.idachev.userservice.service.TokenService;
import dev.idachev.userservice.service.UserService;
import dev.idachev.userservice.web.dto.GenericResponse;
import dev.idachev.userservice.web.dto.ProfileUpdateRequest;
import dev.idachev.userservice.web.dto.UserResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
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
@Tag(name = "User Management")
@Validated
@RequiredArgsConstructor
@Slf4j
public class UserController {

    private final UserService userService;
    private final TokenService tokenService;
    private final AuthenticationService authenticationService;
    private final ProfileService profileService;

    @GetMapping("/user/check-username")
    @Operation(summary = "Check username availability")
    public ResponseEntity<GenericResponse> checkUsernameAvailability(@RequestParam String username) {
        return ResponseEntity.ok(userService.checkUsernameAvailability(username));
    }
    
    @GetMapping("/user/current-user")
    @Operation(
        summary = "Get current user information", 
        description = "Retrieves information about the currently authenticated user."
    )
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<UserResponse> getCurrentUser() {
        return ResponseEntity.ok(profileService.getCurrentUserInfo());
    }
    
    @PostMapping("/user/update-username")
    @Operation(summary = "Update username")
    public ResponseEntity<GenericResponse> updateUsername(
            @Valid @RequestBody ProfileUpdateRequest request,
            @AuthenticationPrincipal UserDetails userDetails) {
        log.debug("Received updateUsername request: {}", request.getUsername());
        
        GenericResponse response = authenticationService.changeUsername(
            userDetails.getUsername(),
            request.getUsername(),
            request.getCurrentPassword());
            
        log.info("Username change processed: from '{}' to '{}'", 
                userDetails.getUsername(), request.getUsername());
        return ResponseEntity.ok(response);
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

    @GetMapping("/users/{id}")
    @Operation(
        summary = "Get user by ID (internal service use)",
        description = "Retrieves basic user information by ID for internal service communication"
    )
    public ResponseEntity<UserResponse> getUserById(@PathVariable UUID id) {
        try {
            return ResponseEntity.ok(userService.getUserById(id));
        } catch (Exception e) {
            log.warn("Error retrieving user by ID {}: {}", id, e.getMessage());
            throw e;
        }
    }

    @GetMapping("/users/{id}/username")
    @Operation(
        summary = "Get username by user ID (internal service use)",
        description = "Lightweight endpoint to retrieve just the username for a given user ID"
    )
    public ResponseEntity<String> getUsernameById(@PathVariable UUID id) {
        try {
            return ResponseEntity.ok(userService.getUsernameById(id));
        } catch (Exception e) {
            log.warn("Error retrieving username for ID {}: {}", id, e.getMessage());
            throw e;
        }
    }
}