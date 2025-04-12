package dev.idachev.userservice.service;

import dev.idachev.userservice.exception.AuthenticationException;
import dev.idachev.userservice.exception.DuplicateUserException;
import dev.idachev.userservice.exception.ResourceNotFoundException;
import dev.idachev.userservice.mapper.DtoMapper;
import dev.idachev.userservice.model.User;
import dev.idachev.userservice.repository.UserRepository;
import dev.idachev.userservice.security.UserPrincipal;
import dev.idachev.userservice.web.dto.AuthResponse;
import dev.idachev.userservice.web.dto.GenericResponse;
import dev.idachev.userservice.web.dto.RegisterRequest;
import dev.idachev.userservice.web.dto.SignInRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * Service responsible for user authentication operations
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository userRepository;
    private final AuthenticationManager authenticationManager;
    private final TokenService tokenService;
    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;
    private final UserService userService;

    /**
     * Registers a new user
     */
    @Transactional
    public AuthResponse register(RegisterRequest request) {
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new DuplicateUserException("Username already exists");
        }
        
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new DuplicateUserException("Email already exists");
        }

        User savedUser = userService.registerUser(request);
        emailService.sendVerificationEmailAsync(savedUser);
        
        return DtoMapper.mapToAuthResponse(
                savedUser,
                true,
                "Registration successful! Please check your email to verify your account."
        );
    }

    /**
     * Authenticates a user
     */
    @Transactional
    public AuthResponse signIn(SignInRequest request) {
        User user = findUserByIdentifier(request.getIdentifier());

        if (!user.isEnabled()) {
            throw new AuthenticationException("Account not verified. Please check your email.");
        }

        if (user.isBanned()) {
            throw new AuthenticationException("Your account has been banned. Please contact support for assistance.");
        }

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(user.getUsername(), request.getPassword()));
        
        UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();

        user.setLastLogin(LocalDateTime.now());
        user.setLoggedIn(true);
        userRepository.save(user);

        String token = tokenService.generateToken(userPrincipal);
        return DtoMapper.mapToAuthResponse(user, token);
    }

    /**
     * Find user by username or email
     */
    private User findUserByIdentifier(String identifier) {
        Optional<User> user = userRepository.findByUsername(identifier);
        if (user.isPresent()) {
            return user.get();
        }
        
        return userRepository.findByEmail(identifier)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with identifier: " + identifier));
    }

    /**
     * Logs out the user
     */
    @Transactional
    public void logout(String token) {
        if (token == null || token.isBlank()) {
            return;
        }

        String tokenWithoutBearer = token.startsWith("Bearer ") ? token.substring(7) : token;
        
        UUID userId = tokenService.extractUserId(tokenWithoutBearer);
        tokenService.blacklistToken(tokenWithoutBearer);
        
        if (userId != null) {
            userRepository.findById(userId).ifPresent(user -> {
                user.setLoggedIn(false);
                userRepository.save(user);
            });
        }
    }

    /**
     * Refreshes a JWT token
     */
    @Transactional
    public AuthResponse refreshToken(String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw new AuthenticationException("Invalid or missing Authorization header");
        }

        String jwtToken = authHeader.substring(7);

        if (tokenService.isTokenBlacklisted(jwtToken)) {
            throw new AuthenticationException("Token is blacklisted or has been logged out");
        }

        UUID userId = tokenService.extractUserId(jwtToken);
        
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found for token"));

        // Blacklist the old token for security
        tokenService.blacklistToken(jwtToken);

        String newToken = tokenService.generateToken(new UserPrincipal(user));
        
        return DtoMapper.mapToAuthResponse(user, newToken);
    }

    /**
     * Changes a user's username
     */
    @Transactional
    public GenericResponse changeUsername(String currentUsername, String newUsername, String password) {
        User user = userRepository.findByUsername(currentUsername)
                .orElseThrow(() -> new ResourceNotFoundException("User not found: " + currentUsername));

        if (!passwordEncoder.matches(password, user.getPassword())) {
            throw new AuthenticationException("Current password is incorrect");
        }

        if (userRepository.existsByUsername(newUsername)) {
            throw new DuplicateUserException("Username already exists");
        }

        user.setUsername(newUsername);
        user.setUpdatedOn(LocalDateTime.now());
        userRepository.save(user);

        tokenService.invalidateUserTokens(user.getId());

        return GenericResponse.builder()
                .status(200)
                .message("Username updated successfully")
                .timestamp(LocalDateTime.now())
                .success(true)
                .build();
    }

    /**
     * Checks a user's ban status
     */
    public Map<String, Object> checkUserBanStatus(String identifier) {
        User user = findUserByIdentifier(identifier);

        Map<String, Object> response = new HashMap<>();
        response.put("username", user.getUsername());
        response.put("banned", user.isBanned());
        response.put("enabled", user.isEnabled());
        return response;
    }
} 