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
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

/**
 * Controller for user profile operations
 */
@Slf4j
@RestController
@RequestMapping("/api/v1")
@Tag(name = "User Profile", description = "Endpoints for managing user profiles")
public class ProfileController {

    private final ProfileService profileService;

    @Autowired
    public ProfileController(ProfileService profileService) {
        this.profileService = profileService;
    }

    @GetMapping("/profile")
    @Operation(
            summary = "Get user profile",
            description = "Retrieves the current user's profile information",
            security = @SecurityRequirement(name = "bearerAuth")
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Profile retrieved successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    public ResponseEntity<UserResponse> getProfile() {
        log.info("Profile request received");
        UserResponse user = profileService.getCurrentUserInfo();
        log.info("Profile retrieved for user: {}", user.getUsername());
        return ResponseEntity.ok(user);
    }

    @GetMapping("/profile/{username}")
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
        log.info("Profile request received for username: {}", username);
        UserResponse user = profileService.getUserInfo(username);
        log.info("Profile retrieved for user: {}", user.getUsername());
        return ResponseEntity.ok(user);
    }

    @PutMapping("/profile")
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
            @Valid @ModelAttribute ProfileUpdateRequest request,
            @AuthenticationPrincipal UserDetails userDetails) {
        log.info("Updating profile for user: {}", userDetails.getUsername());

        // Let exceptions propagate to GlobalExceptionHandler for proper status codes
        UserResponse updatedUser = profileService.updateProfile(userDetails.getUsername(), request);

        log.info("Profile updated successfully");
        return ResponseEntity.ok(updatedUser);
    }

    // Compatibility endpoints for older clients using the /api/v1/user/profile path

    @GetMapping("/user/profile")
    public ResponseEntity<UserResponse> getProfileCompat() {
        log.info("Compatibility endpoint: Profile request received");
        return getProfile();
    }

    @GetMapping("/user/profile/{username}")
    public ResponseEntity<UserResponse> getProfileByUsernameCompat(@PathVariable String username) {
        log.info("Compatibility endpoint: Profile request for username: {}", username);
        return getProfileByUsername(username);
    }

    @PutMapping("/user/profile")
    public ResponseEntity<UserResponse> updateProfileCompat(
            @Valid @ModelAttribute ProfileUpdateRequest request,
            @AuthenticationPrincipal UserDetails userDetails) {
        log.info("Compatibility endpoint: Updating profile for user: {}", userDetails.getUsername());
        return updateProfile(request, userDetails);
    }

    // Compatibility endpoint for older clients using the /api/v1/auth/profile path

    @GetMapping("/auth/profile")
    public ResponseEntity<UserResponse> getAuthProfileCompat() {
        log.info("Auth compatibility endpoint: Profile request received");
        return getProfile();
    }

    // Add endpoint for inter-service communication
    @GetMapping("/user/current-user")
    public ResponseEntity<UserResponse> getCurrentUser(@RequestHeader("Authorization") String token) {
        log.info("Current user request received from service");
        UserResponse user = profileService.getCurrentUserInfo();
        log.info("Current user info retrieved for: {}", user.getUsername());
        return ResponseEntity.ok(user);
    }
} 