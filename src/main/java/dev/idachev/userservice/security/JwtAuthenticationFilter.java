package dev.idachev.userservice.security;

import dev.idachev.userservice.config.JwtConfig;
import dev.idachev.userservice.service.TokenBlacklistService;
import dev.idachev.userservice.service.UserDetailsService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

/**
 * Filter for JWT authentication in requests
 */
@Component
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";
    private static final String CONTENT_TYPE_JSON = "application/json";
    private static final String ERROR_RESPONSE = "{\"error\":\"Unauthorized\",\"message\":\"Token is no longer valid\"}";

    private final AntPathMatcher pathMatcher = new AntPathMatcher();

    // Paths that don't require authentication (using Ant path matching)
    private static final List<String> PUBLIC_PATHS = Arrays.asList(
            // Authentication endpoints
            "/api/v1/auth/signin",
            "/api/v1/auth/signup",
            "/api/v1/auth/logout",
            "/api/v1/auth/refresh-token",
            "/api/v1/auth/check-status",

            // Verification endpoints
            "/api/v1/verification/status",
            "/api/v1/verification/resend",
            "/api/v1/verification/verify/**",
            
            // User endpoints that don't require auth
            "/api/v1/user/check-username",
            
            // Profile endpoints
            "/api/v1/profile",
            "/api/v1/profile/**",

            // Contact form endpoint
            "/api/v1/contact/submit",

            // Swagger UI and API docs
            "/swagger-ui/**",
            "/api-docs/**",
            "/v3/api-docs/**",

            // Static resources
            "/css/**", 
            "/js/**", 
            "/images/**",
            "/favicon.ico"
    );

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
    protected boolean shouldNotFilter(@NonNull HttpServletRequest request) {
        String requestPath = request.getRequestURI();
        boolean isPublicPath = PUBLIC_PATHS.stream()
                .anyMatch(pattern -> pathMatcher.match(pattern, requestPath));
        
        if (isPublicPath) {
            log.debug("Skipping auth filter for public path: {}", requestPath);
        }
        
        return isPublicPath;
    }

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain) throws ServletException, IOException {
        
        try {
            String jwtToken = extractTokenFromRequest(request);
            
            if (StringUtils.hasText(jwtToken)) {
                // Handle blacklisted tokens
                if (tokenBlacklistService.isBlacklisted(jwtToken)) {
                    rejectBlacklistedToken(response);
                    return;
                }
                
                // Skip authentication if already authenticated
                if (SecurityContextHolder.getContext().getAuthentication() == null) {
                    authenticateToken(jwtToken, request);
                }
            }
        } catch (Exception e) {
            log.error("Authentication error: {}", e.getMessage());
        }

        filterChain.doFilter(request, response);
    }
    
    /**
     * Extracts JWT token from request header
     */
    private String extractTokenFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader(AUTHORIZATION_HEADER);
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(BEARER_PREFIX)) {
            return bearerToken.substring(BEARER_PREFIX.length());
        }
        return null;
    }
    
    /**
     * Rejects a request with a blacklisted token
     */
    private void rejectBlacklistedToken(HttpServletResponse response) throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(CONTENT_TYPE_JSON);
        response.getWriter().write(ERROR_RESPONSE);
    }
    
    /**
     * Validates and authenticates a JWT token
     */
    private void authenticateToken(String token, HttpServletRequest request) {
        UUID userId = jwtConfig.extractUserId(token);
        if (userId == null) {
            return;
        }
        
        try {
            UserDetails userDetails = userDetailsService.loadUserById(userId);
            
            if (jwtConfig.validateToken(token, userDetails)) {
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities());
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);
                log.debug("Successfully authenticated user ID: {}", userId);
            }
        } catch (UsernameNotFoundException e) {
            log.warn("User not found for token with ID {}", userId);
        } catch (Exception e) {
            log.warn("Token validation failed: {}", e.getMessage());
        }
    }
}
