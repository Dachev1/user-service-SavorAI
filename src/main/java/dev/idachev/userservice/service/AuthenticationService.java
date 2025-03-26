package dev.idachev.userservice.service;

import dev.idachev.userservice.config.JwtConfig;
import dev.idachev.userservice.exception.AuthenticationException;
import dev.idachev.userservice.exception.ResourceNotFoundException;
import dev.idachev.userservice.mapper.DtoMapper;
import dev.idachev.userservice.model.User;
import dev.idachev.userservice.repository.UserRepository;
import dev.idachev.userservice.security.UserPrincipal;
import dev.idachev.userservice.web.dto.AuthResponse;
import dev.idachev.userservice.web.dto.GenericResponse;
import dev.idachev.userservice.web.dto.LoginRequest;
import dev.idachev.userservice.web.dto.UserResponse;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Date;
import java.util.Optional;

@Service
@Slf4j
public class AuthenticationService {

    private final UserRepository userRepository;
    private final UserService userService;
    private final JwtConfig jwtConfig;
    private final AuthenticationManager authenticationManager;
    private final TokenBlacklistService tokenBlacklistService;

    @Autowired
    public AuthenticationService(
            UserRepository userRepository,
            UserService userService,
            JwtConfig jwtConfig,
            AuthenticationManager authenticationManager,
            TokenBlacklistService tokenBlacklistService) {
        this.userRepository = userRepository;
        this.userService = userService;
        this.jwtConfig = jwtConfig;
        this.authenticationManager = authenticationManager;
        this.tokenBlacklistService = tokenBlacklistService;
    }

    /**
     * Authenticates a user
     *
     * @param request Login credentials
     * @return AuthResponse with JWT token and user information
     */
    @Transactional
    public AuthResponse login(LoginRequest request) {
        try {
            User user = userService.findByUsernameOrEmail(request.getIdentifier());

            if (user.isLoggedIn()) {
                log.warn("User {} attempted to log in while already logged in", user.getEmail());
                throw new AuthenticationException("Already logged in. Please log out first.");
            }

            if (!user.isEnabled()) {
                throw new AuthenticationException("Account not verified. Please check your email.");
            }

            // Authenticate user
            Authentication authentication = authenticate(request);
            UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();
            user = userPrincipal.user();

            // Update user login status
            updateUserOnLogin(user);

            // Generate JWT token
            String token = jwtConfig.generateToken(userPrincipal);

            log.info("User logged in: {}", user.getEmail());
            return DtoMapper.mapToAuthResponse(user, token);
        } catch (ResourceNotFoundException e) {
            // Re-throw original exception to keep test behavior
            throw e;
        } catch (BadCredentialsException e) {
            log.error("Login failed: Invalid credentials for {}", request.getIdentifier());
            throw e;
        } catch (Exception e) {
            log.error("Login failed: {}", e.getMessage());
            throw new AuthenticationException("Authentication failed", e);
        }
    }

    /**
     * Logs out the current user and invalidates the token
     *
     * @param authHeader Authorization header containing the JWT token
     * @return Response with logout status
     */
    @Transactional
    public GenericResponse logout(String authHeader) {
        boolean userLoggedOutFromContext = logoutAuthenticatedUser();
        boolean userLoggedOut = userLoggedOutFromContext;

        // If no user was found in the security context, try to extract user from token
        if (!userLoggedOutFromContext && authHeader != null && authHeader.startsWith("Bearer ")) {
            try {
                String jwtToken = authHeader.substring(7);
                String username = jwtConfig.extractUsername(jwtToken);

                if (username != null && !username.isEmpty()) {
                    log.info("Attempting to logout user from token: {}", username);
                    Optional<User> userOpt = userRepository.findByUsername(username)
                            .or(() -> userRepository.findByEmail(username));

                    if (userOpt.isPresent()) {
                        User user = userOpt.get();
                        user.setLoggedIn(false);
                        userRepository.save(user);
                        log.info("User logged out via token: {}", user.getEmail());
                        userLoggedOut = true;
                    }
                }
            } catch (Exception e) {
                log.warn("Failed to extract user from token: {}", e.getMessage());
            }
        }

        boolean tokenBlacklisted = blacklistToken(authHeader);

        if (!userLoggedOut && !tokenBlacklisted) {
            log.info("Logout called but no active user session or valid token found");
        }

        return GenericResponse.builder()
                .status(200)
                .message("Logged out successfully")
                .timestamp(LocalDateTime.now())
                .build();
    }

    /**
     * Logs out the currently authenticated user
     *
     * @return true if a user was logged out, false otherwise
     */
    private boolean logoutAuthenticatedUser() {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            if (!isAuthenticatedUser(authentication)) {
                return false;
            }

            UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();
            User user = userPrincipal.user();
            user.setLoggedIn(false);
            userRepository.save(user);
            log.info("User logged out: {}", user.getEmail());

            return true;
        } finally {
            SecurityContextHolder.clearContext();
        }
    }

    /**
     * Helper method to extract and blacklist a token from the Authorization header
     *
     * @return true if token was blacklisted, false otherwise
     */
    private boolean blacklistToken(String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return false;
        }

        try {
            String jwtToken = authHeader.substring(7);
            Date expiryDate = jwtConfig.extractExpiration(jwtToken);

            if (expiryDate != null) {
                tokenBlacklistService.blacklistToken(jwtToken, expiryDate.getTime());
                log.info("Token blacklisted successfully, expires at: {}", expiryDate);
                return true;
            }
            return false;
        } catch (ExpiredJwtException e) {
            // No need to blacklist an already expired token
            log.info("Token already expired, no need to blacklist");
            return false;
        } catch (JwtException e) {
            log.warn("Invalid JWT token during blacklisting: {}", e.getMessage());
            return false;
        } catch (Exception e) {
            log.error("Error blacklisting token: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Gets verification status for a user
     *
     * @param identifier User's email or username
     * @return AuthResponse with verification status
     */
    public AuthResponse getVerificationStatus(String identifier) {
        User user = userService.findByUsernameOrEmail(identifier);
        String token = "";

        if (user.isEnabled()) {
            UserPrincipal userPrincipal = new UserPrincipal(user);
            token = jwtConfig.generateToken(userPrincipal);
        }

        return DtoMapper.mapToAuthResponse(user, token);
    }

    /**
     * Gets the currently authenticated user
     *
     * @return User object
     */
    public User getCurrentUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (!isAuthenticatedUser(authentication)) {
            throw new AuthenticationException("User not authenticated");
        }

        UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();
        return userPrincipal.user();
    }

    /**
     * Gets current user information as a DTO
     *
     * @return UserResponse DTO
     */
    public UserResponse getCurrentUserInfo() {
        User user = getCurrentUser();
        return DtoMapper.mapToUserResponse(user);
    }

    /**
     * Gets user information as a DTO, optionally by username or email
     *
     * @param identifier Optional username or email to look up specific user
     * @return UserResponse DTO
     */
    public UserResponse getCurrentUserInfo(String identifier) {
        if (identifier == null || identifier.isEmpty()) {
            return getCurrentUserInfo();
        }

        User user = userService.findByUsernameOrEmail(identifier);
        return DtoMapper.mapToUserResponse(user);
    }

    private Authentication authenticate(LoginRequest request) {
        if (request.getIdentifier() == null || request.getIdentifier().isEmpty()) {
            throw new IllegalArgumentException("Username or email cannot be empty");
        }

        Authentication auth = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getIdentifier(),
                        request.getPassword()
                )
        );

        SecurityContextHolder.getContext().setAuthentication(auth);
        return auth;
    }

    private void updateUserOnLogin(User user) {
        user.updateLastLogin();
        user.setLoggedIn(true);
        userRepository.save(user);
    }

    private boolean isAuthenticatedUser(Authentication authentication) {
        return Optional.ofNullable(authentication)
                .filter(Authentication::isAuthenticated)
                .map(Authentication::getPrincipal)
                .filter(principal -> principal instanceof UserPrincipal)
                .isPresent();
    }
} 