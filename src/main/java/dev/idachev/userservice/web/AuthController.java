package dev.idachev.userservice.web;

import dev.idachev.userservice.service.AuthenticationService;
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
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * Controller for authentication operations
 */
@Slf4j
@RestController
@RequestMapping(path = "/api/v1/auth", produces = MediaType.APPLICATION_JSON_VALUE)
@Tag(name = "Authentication", description = "Endpoints for user authentication")
public class AuthController {

    private final AuthenticationService authService;
    
    public AuthController(AuthenticationService authService) {
        this.authService = authService;
    }

    @PostMapping(path = "/signup", consumes = MediaType.APPLICATION_JSON_VALUE)
    @Operation(summary = "Sign up new user", description = "Creates a new user account and sends verification email")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "201", description = "User signed up successfully",
                    content = @Content(schema = @Schema(implementation = AuthResponse.class))),
            @ApiResponse(responseCode = "400", description = "Invalid input data"),
            @ApiResponse(responseCode = "409", description = "Username or email already exists")
    })
    public ResponseEntity<AuthResponse> signup(@Valid @RequestBody RegisterRequest request) {
        log.debug("Signup request received for email: {}", request.getEmail());
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
        log.debug("Sign in request received for user: {}", request.getIdentifier());
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
    @Operation(summary = "Log out the current user", description = "Logs out the currently authenticated user, invalidating their session token and updating their status")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "User successfully logged out",
                    content = @Content(schema = @Schema(implementation = GenericResponse.class))),
            @ApiResponse(responseCode = "401", description = "Unauthorized - invalid credentials")
    })
    public ResponseEntity<GenericResponse> logout(
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        log.debug("Logout request received");
        return ResponseEntity.ok(authService.logout(authHeader));
    }

    @PostMapping(path = "/change-username", consumes = MediaType.APPLICATION_JSON_VALUE)
    @Operation(summary = "Change username", description = "Changes the username for an authenticated user", 
               security = @SecurityRequirement(name = "bearerAuth"))
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Username changed successfully",
                    content = @Content(schema = @Schema(implementation = GenericResponse.class))),
            @ApiResponse(responseCode = "400", description = "Invalid username format"),
            @ApiResponse(responseCode = "401", description = "Password incorrect or unauthorized"),
            @ApiResponse(responseCode = "409", description = "Username already taken")
    })
    public ResponseEntity<GenericResponse> changeUsername(
            @Valid @RequestBody ProfileUpdateRequest request,
            @AuthenticationPrincipal UserDetails userDetails) {
        log.debug("Username change request received from: {}", userDetails.getUsername());
        return ResponseEntity.ok(authService.changeUsername(
                userDetails.getUsername(),
                request.getUsername(),
                request.getCurrentPassword()));
    }

    @GetMapping("/check-status")
    @Operation(summary = "Check user status", description = "Checks if a user is banned by their username or email")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "User status check successful"),
            @ApiResponse(responseCode = "404", description = "User not found")
    })
    public ResponseEntity<Map<String, Object>> checkUserStatus(@RequestParam String identifier) {
        log.debug("User status check received for: {}", identifier);
        return ResponseEntity.ok(authService.checkUserBanStatus(identifier));
    }
}