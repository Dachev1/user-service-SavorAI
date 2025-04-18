package dev.idachev.userservice.web;

import dev.idachev.userservice.security.UserPrincipal;
import dev.idachev.userservice.service.ProfileService;
import dev.idachev.userservice.util.ResponseBuilder;
import dev.idachev.userservice.web.dto.GenericResponse;
import dev.idachev.userservice.web.dto.PasswordChangeRequest;
import dev.idachev.userservice.web.dto.UserResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

/**
 * Controller for user profile operations (viewing own profile, password change, account deletion).
 */
@RestController
@RequestMapping("/api/v1/profile")
@Tag(name = "Profile", description = "Endpoints for managing the authenticated user's profile")
@RequiredArgsConstructor
public class ProfileController {

    private final ProfileService profileService;
    
    @GetMapping("/me")
    @Operation(
            summary = "Get current user's profile",
            description = "Retrieves the profile information for the currently authenticated user.",
            security = @SecurityRequirement(name = "bearerAuth")
    )
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Profile retrieved successfully"),
        @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<UserResponse> getCurrentUserProfile(
            @AuthenticationPrincipal UserPrincipal principal) {
        UserResponse userResponse = profileService.getUserInfoByUsername(principal.getUsername());
        return ResponseEntity.ok(userResponse);
    }

    @DeleteMapping("/me")
    @Operation(
            summary = "Delete current user's account",
            description = "Permanently deletes the currently authenticated user's account.",
            security = @SecurityRequirement(name = "bearerAuth")
    )
     @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Account deleted successfully",
                 content = @Content(schema = @Schema(implementation = GenericResponse.class))),
        @ApiResponse(responseCode = "401", description = "Unauthorized"),
        @ApiResponse(responseCode = "404", description = "User not found (should not happen for authenticated user)")
    })
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<GenericResponse> deleteCurrentUserAccount(
            @AuthenticationPrincipal UserPrincipal principal) {
        profileService.deleteAccount(principal.getUsername());
        return ResponseEntity.ok(ResponseBuilder.success("Account successfully deleted"));
    }
    
    @PostMapping("/password")
    @Operation(
            summary = "Change current user's password",
            description = "Changes the password for the currently authenticated user. Requires current password.",
            security = @SecurityRequirement(name = "bearerAuth")
    )
     @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Password changed successfully",
                content = @Content(schema = @Schema(implementation = GenericResponse.class))),
        @ApiResponse(responseCode = "400", description = "Invalid input (e.g., passwords don't match, missing fields)"),
        @ApiResponse(responseCode = "401", description = "Unauthorized or current password incorrect")
    })
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<GenericResponse> changeCurrentUserPassword(
            @AuthenticationPrincipal UserPrincipal principal,
            @Valid @RequestBody PasswordChangeRequest passwordChangeRequest) {
        profileService.changePassword(
                principal.getUsername(),
                passwordChangeRequest
        );
        return ResponseEntity.ok(ResponseBuilder.success("Password changed successfully"));
    }
} 