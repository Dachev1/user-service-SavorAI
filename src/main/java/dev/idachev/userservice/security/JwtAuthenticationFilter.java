package dev.idachev.userservice.security;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import dev.idachev.userservice.config.JwtConfig;
import dev.idachev.userservice.service.TokenBlacklistService;
import dev.idachev.userservice.service.UserDetailsService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

/**
 * Filter for validating JWT tokens in incoming requests
 */
@Component
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";

    // Paths that don't require authentication
    private static final List<String> PUBLIC_PATHS = Arrays.asList(
            "/api/v1/auth/signin",
            "/api/v1/auth/signup",
            "/api/v1/user/verify-email/",
            "/api/v1/verification/",
            "/api/v1/auth/logout",
            "/api/v1/auth/refresh-token",
            "/swagger-ui/",
            "/api-docs/",
            "/v3/api-docs/",
            "/css/", "/js/", "/images/",
            "/actuator/",
            "/favicon.ico");

    private final JwtConfig jwtConfig;
    private final UserDetailsService userDetailsService;
    private final TokenBlacklistService tokenBlacklistService;

    @Autowired
    public JwtAuthenticationFilter(
            JwtConfig jwtConfig,
            UserDetailsService userDetailsService,
            TokenBlacklistService tokenBlacklistService) {
        this.jwtConfig = jwtConfig;
        this.userDetailsService = userDetailsService;
        this.tokenBlacklistService = tokenBlacklistService;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String requestPath = request.getRequestURI();
        String method = request.getMethod();

        // Always skip filtering for logout requests (GET or POST)
        if (requestPath.startsWith("/api/v1/auth/logout")) {
            log.debug("Skipping JWT filter for logout request: {} {}", method, requestPath);
            return true;
        }

        // Skip for other public paths
        for (String publicPath : PUBLIC_PATHS) {
            if (requestPath.startsWith(publicPath)) {
                return true;
            }
        }

        return false;
    }

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain) throws ServletException, IOException {
        try {
            String jwtToken = getJwtFromRequest(request);

            if (StringUtils.hasText(jwtToken) && isValidForAuthentication(jwtToken)) {
                authenticateWithToken(jwtToken, request);
            }
        } catch (Exception e) {
            log.error("Cannot set user authentication: {}", e.getMessage());
        }

        filterChain.doFilter(request, response);
    }

    /**
     * Checks if a token is valid for authentication
     */
    private boolean isValidForAuthentication(String token) {
        // Already authenticated or token is blacklisted
        return !tokenBlacklistService.isBlacklisted(token) &&
                SecurityContextHolder.getContext().getAuthentication() == null;
    }

    /**
     * Authenticates a user with a valid JWT token
     */
    private void authenticateWithToken(String jwtToken, HttpServletRequest request) {
        try {
            UUID userId = jwtConfig.extractUserId(jwtToken);
            String tokenUsername = jwtConfig.extractUsername(jwtToken);

            if (userId == null) {
                log.warn("Token has no user ID");
                return;
            }

            // Always load by ID to get the most current user data
            UserDetails userDetails = userDetailsService.loadUserById(userId);

            if (jwtConfig.validateToken(jwtToken, userDetails)) {
                // Create authentication object and set it in the security context
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities());
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);

                // Log username information for debugging
                String currentUsername = userDetails.getUsername();
                log.debug("Authenticated user: {}", currentUsername);

                // Only log username mismatch if needed
                if (!currentUsername.equals(tokenUsername)) {
                    log.debug("Note: Token username '{}' differs from current username '{}'",
                            tokenUsername, currentUsername);
                }
            }
        } catch (UsernameNotFoundException e) {
            log.warn("User not found for token: {}", e.getMessage());
        } catch (Exception e) {
            log.warn("Token validation failed: {}", e.getMessage());
        }
    }

    private String getJwtFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader(AUTHORIZATION_HEADER);
        return StringUtils.hasText(bearerToken) && bearerToken.startsWith(BEARER_PREFIX)
                ? bearerToken.substring(BEARER_PREFIX.length())
                : null;
    }
}
