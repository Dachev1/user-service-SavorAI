package dev.idachev.userservice.service;

import dev.idachev.userservice.config.JwtConfig;
import dev.idachev.userservice.exception.AuthenticationException;
import dev.idachev.userservice.exception.ResourceNotFoundException;
import dev.idachev.userservice.mapper.DtoMapper;
import dev.idachev.userservice.model.User;
import dev.idachev.userservice.repository.UserRepository;
import dev.idachev.userservice.web.dto.AuthResponse;
import dev.idachev.userservice.web.dto.ErrorResponse;
import dev.idachev.userservice.web.dto.LoginRequest;
import dev.idachev.userservice.web.dto.UserResponse;
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
    private final JwtConfig jwtConfig;
    private final AuthenticationManager authenticationManager;
    private final TokenBlacklistService tokenBlacklistService;

    @Autowired
    public AuthenticationService(UserRepository userRepository, JwtConfig jwtConfig, AuthenticationManager authenticationManager,
                               TokenBlacklistService tokenBlacklistService) {
        this.userRepository = userRepository;
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

        User user = findUserByEmail(request.getEmail());
        checkUserCanLogin(user);

        try {
            Authentication authentication = authenticate(request);
            user = (User) authentication.getPrincipal();

            updateUserOnLogin(user);
            String token = jwtConfig.generateToken(user);

            log.info("User logged in: {}", user.getEmail());
            return DtoMapper.mapToAuthResponse(user, token);
        } catch (BadCredentialsException e) {

            log.error("Login failed: Invalid credentials for {}", request.getEmail());
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
    public ErrorResponse logout(String authHeader) {
        try {
            Optional.ofNullable(SecurityContextHolder.getContext().getAuthentication())
                .filter(this::isAuthenticatedUser)
                .map(authentication -> (User) authentication.getPrincipal())
                .ifPresent(user -> {
                    user.setLoggedIn(false);
                    userRepository.save(user);
                    log.info("User logged out: {}", user.getEmail());
                });
            
            // Extract and blacklist the token
            blacklistToken(authHeader);
        } finally {
            SecurityContextHolder.clearContext();
        }

        return ErrorResponse.builder()
                .status(200)
                .message("Logged out successfully")
                .timestamp(LocalDateTime.now())
                .build();
    }

    /**
     * Helper method to extract and blacklist a token from the Authorization header
     */
    private void blacklistToken(String authHeader) {
        try {
            Optional.ofNullable(authHeader)
                .filter(header -> header.startsWith("Bearer "))
                .map(header -> header.substring(7))
                .ifPresent(jwtToken -> {
                    Date expiryDate = jwtConfig.extractExpiration(jwtToken);
                    if (expiryDate != null) {
                        tokenBlacklistService.blacklistToken(jwtToken, expiryDate.getTime());
                        log.info("Token blacklisted successfully, expires at: {}", expiryDate);
                    }
                });
        } catch (Exception e) {
            log.error("Error blacklisting token: {}", e.getMessage());
        }
    }

    /**
     * Gets user's verification status
     *
     * @param email User email
     * @return Auth response with verification status
     */
    public AuthResponse getVerificationStatus(String email) {

        User user = findUserByEmail(email);
        String token = user.isEnabled() ? jwtConfig.generateToken(user) : "";

        return DtoMapper.mapToAuthResponse(user, token);
    }

    /**
     * Gets currently authenticated user
     *
     * @return Current user
     */
    public User getCurrentUser() {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (!isAuthenticatedUser(authentication)) {
            throw new AuthenticationException("User not authenticated");
        }

        return (User) authentication.getPrincipal();
    }

    /**
     * Gets currently logged in user information
     *
     * @return User information response
     */
    public UserResponse getCurrentUserInfo() {

        User user = getCurrentUser();

        return DtoMapper.mapToUserResponse(user);
    }

    // Private helper methods

    private User findUserByEmail(String email) {

        return userRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with email: " + email));
    }

    private void checkUserCanLogin(User user) {

        if (user.isLoggedIn()) {
            log.warn("User {} attempted to log in while already logged in", user.getEmail());
            throw new AuthenticationException("Already logged in. Please log out first.");
        }

        if (!user.isEnabled()) {
            throw new AuthenticationException("Account not verified. Please check your email.");
        }
    }

    private Authentication authenticate(LoginRequest request) {

        Authentication auth = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
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
                .filter(principal -> principal instanceof User)
                .isPresent();
    }
} 