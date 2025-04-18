package dev.idachev.userservice.web;

import dev.idachev.userservice.security.UserPrincipal;
import dev.idachev.userservice.service.AuthenticationService;
import dev.idachev.userservice.util.ResponseBuilder;
import dev.idachev.userservice.web.dto.*;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

/**
 * Controller for authentication operations
 */
@Slf4j
@RestController
@RequestMapping(path = "/api/v1/auth", produces = MediaType.APPLICATION_JSON_VALUE)
@Tag(name = "Authentication", description = "Endpoints for user authentication")
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationService authService;
    
    @PostMapping(path = "/signup", consumes = MediaType.APPLICATION_JSON_VALUE)
    @Operation(summary = "Sign up new user", description = "Creates a new user account and sends verification email")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "201", description = "User signed up successfully",
                    content = @Content(schema = @Schema(implementation = AuthResponse.class))),
            @ApiResponse(responseCode = "400", description = "Invalid input data"),
            @ApiResponse(responseCode = "409", description = "Username or email already exists")
    })
    public ResponseEntity<AuthResponse> signup(@Valid @RequestBody RegisterRequest request) {
        log.debug("Signup request received for email: {}", request.email());
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(authService.register(request));
    }

    @PostMapping(path = "/signin", consumes = MediaType.APPLICATION_JSON_VALUE)
    @Operation(summary = "Authenticate user", description = "Validates credentials and returns JWT token. Supports sign in with either username or email.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Authentication successful",
                    content = @Content(schema = @Schema(implementation = AuthResponse.class))),
            @ApiResponse(responseCode = "400", description = "Invalid input or already signed in"),
            @ApiResponse(responseCode = "401", description = "Invalid credentials")
    })
    public ResponseEntity<AuthResponse> signin(@Valid @RequestBody SignInRequest request) {
        log.debug("Sign in request received for user: {}", request.identifier());
        return ResponseEntity.ok(authService.signIn(request));
    }

    @PostMapping("/refresh-token")
    @Operation(summary = "Refresh token", description = "Issues a new access token using a valid refresh token", 
               security = @SecurityRequirement(name = "bearerAuth"))
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Token refreshed successfully",
                    content = @Content(schema = @Schema(implementation = AuthResponse.class))),
            @ApiResponse(responseCode = "401", description = "Invalid or expired refresh token")
    })
    public ResponseEntity<AuthResponse> refreshToken(HttpServletRequest request) {
        log.debug("Token refresh request received");
        return ResponseEntity.ok(authService.refreshToken(request.getHeader("Authorization")));
    }

    @PostMapping("/logout")
    @Operation(summary = "Log out the current user", description = "Invalidates the current user's session token.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "User successfully logged out",
                    content = @Content(schema = @Schema(implementation = GenericResponse.class))),
            @ApiResponse(responseCode = "401", description = "Unauthorized or invalid token")
    })
    @SecurityRequirement(name = "bearerAuth")
    public ResponseEntity<GenericResponse> logout(
            @RequestHeader(value = "Authorization") String authHeader) {
        log.debug("Logout request received");
        authService.logout(authHeader);
        return ResponseEntity.ok(ResponseBuilder.success("Successfully logged out"));
    }

    @PostMapping(path = "/change-username", consumes = MediaType.APPLICATION_JSON_VALUE)
    @Operation(summary = "Change username", description = "Changes the username for the currently authenticated user. Requires current password.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Username changed successfully",
                    content = @Content(schema = @Schema(implementation = GenericResponse.class))),
            @ApiResponse(responseCode = "400", description = "Invalid input (e.g., format, missing fields)"),
            @ApiResponse(responseCode = "401", description = "Current password incorrect or unauthorized"),
            @ApiResponse(responseCode = "404", description = "Authenticated user not found (should not happen)"),
            @ApiResponse(responseCode = "409", description = "New username is already taken")
    })
    @SecurityRequirement(name = "bearerAuth")
    public ResponseEntity<GenericResponse> changeUsername(
            @Valid @RequestBody ProfileUpdateRequest request,
            @AuthenticationPrincipal UserPrincipal principal) {
        
        if (principal == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        String currentUsername = principal.getUsername();
        log.debug("Username change request received from: {}", currentUsername);
        
        authService.changeUsername(
                currentUsername,
                request.getUsername(),
                request.getCurrentPassword()
        );
        return ResponseEntity.ok(ResponseBuilder.success("Username updated successfully"));
    }

    @GetMapping("/check-status")
    @Operation(summary = "Check user status", description = "Checks if a user is enabled and not banned, by username or email.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "User status retrieved successfully",
                    content = @Content(schema = @Schema(implementation = UserStatusResponse.class))),
            @ApiResponse(responseCode = "404", description = "User not found with the given identifier")
    })
    public ResponseEntity<UserStatusResponse> checkUserStatus(@RequestParam String identifier) {
        log.debug("User status check received for: {}", identifier);
        UserStatusResponse status = authService.checkUserStatus(identifier);
        return ResponseEntity.ok(status);
    }
}