package dev.idachev.userservice.web;

import dev.idachev.userservice.service.ProfileService;
import dev.idachev.userservice.web.dto.ProfileUpdateRequest;
import dev.idachev.userservice.web.dto.UserResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;

/**
 * Controller for user profile operations
 */
@RestController
@RequestMapping("/api/v1/profile")
@Tag(name = "Profile", description = "User profile endpoints")
@RequiredArgsConstructor
public class ProfileController {

    private final ProfileService profileService;

    @GetMapping
    @Operation(
            summary = "Get current user profile",
            description = "Retrieves the current authenticated user's profile information",
            security = @SecurityRequirement(name = "bearerAuth")
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Profile retrieved successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    public ResponseEntity<UserResponse> getProfile() {
        return ResponseEntity.ok(profileService.getCurrentUserInfo());
    }

    @GetMapping("/{username}")
    @Operation(
            summary = "Get user profile by username",
            description = "Retrieves a user's profile information by username",
            security = @SecurityRequirement(name = "bearerAuth")
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Profile retrieved successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "User not found")
    })
    public ResponseEntity<UserResponse> getProfileByUsername(@PathVariable String username) {
        return ResponseEntity.ok(profileService.getUserInfo(username));
    }

    @PutMapping
    @Operation(
            summary = "Update user profile",
            description = "Update user profile information including username",
            security = @SecurityRequirement(name = "bearerAuth")
    )
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Profile updated successfully"),
            @ApiResponse(responseCode = "400", description = "Invalid input data"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "409", description = "Username already taken")
    })
    public ResponseEntity<UserResponse> updateProfile(
            @Valid @RequestBody ProfileUpdateRequest request,
            @AuthenticationPrincipal UserDetails userDetails,
            Principal principal) {
        String username = userDetails != null ? userDetails.getUsername() : principal.getName();
        return ResponseEntity.ok(profileService.updateProfile(username, request));
    }
    
    // Compatibility endpoints
    
    @GetMapping("/profile")
    public ResponseEntity<UserResponse> getProfileCompat() {
        return ResponseEntity.ok(profileService.getCurrentUserInfo());
    }
    
    @GetMapping("/profile/{username}")
    public ResponseEntity<UserResponse> getProfileByUsernameCompat(@PathVariable String username) {
        return ResponseEntity.ok(profileService.getUserInfo(username));
    }
    
    @PutMapping("/profile")
    public ResponseEntity<UserResponse> updateProfileCompat(
            @Valid @RequestBody ProfileUpdateRequest request,
            @AuthenticationPrincipal UserDetails userDetails,
            Principal principal) {
        String username = userDetails != null ? userDetails.getUsername() : principal.getName();
        return ResponseEntity.ok(profileService.updateProfile(username, request));
    }
    
    @GetMapping("/user/current-user")
    public ResponseEntity<UserResponse> getCurrentUser() {
        return ResponseEntity.ok(profileService.getCurrentUserInfo());
    }
    
    @GetMapping("/user/profile")
    public ResponseEntity<UserResponse> getUserProfile() {
        return ResponseEntity.ok(profileService.getCurrentUserInfo());
    }
    
    @GetMapping("/user/profile/{username}")
    public ResponseEntity<UserResponse> getUserProfileByUsername(@PathVariable String username) {
        return ResponseEntity.ok(profileService.getUserInfo(username));
    }
    
    @GetMapping("/auth/profile")
    public ResponseEntity<UserResponse> getAuthProfile() {
        return ResponseEntity.ok(profileService.getCurrentUserInfo());
    }
} 