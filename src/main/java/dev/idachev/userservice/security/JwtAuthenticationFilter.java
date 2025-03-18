package dev.idachev.userservice.security;

import dev.idachev.userservice.config.JwtConfig;
import dev.idachev.userservice.service.TokenBlacklistService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);
    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";

    // More concise path patterns
    private static final List<String> PUBLIC_PATHS = Arrays.asList(
            "/api/v1/user/login",
            "/api/v1/user/register",
            "/api/v1/user/verify",
            "/api/v1/user/verify-email",
            "/api/v1/user/verification-status",
            "/css/", "/js/", "/images/", "/webjars/",
            "/actuator/", "/favicon.ico"
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
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        return path.startsWith("/api/v1/user/verify/") ||
                path.startsWith("/api/v1/user/verify-email/") ||
                PUBLIC_PATHS.stream().anyMatch(path::startsWith);
    }

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {
        try {
            String jwt = getJwtFromRequest(request);

            if (StringUtils.hasText(jwt)) {
                // Check if token is blacklisted before any other validation
                if (tokenBlacklistService.isBlacklisted(jwt)) {
                    logger.warn("Rejected blacklisted token");
                    // Continue with filter chain - security context remains null
                } else if (SecurityContextHolder.getContext().getAuthentication() == null) {
                    // Only proceed with token validation if not already authenticated
                    processValidToken(jwt, request);
                }
            }
        } catch (Exception e) {
            logger.error("Cannot set user authentication: {}", e.getMessage());
        }

        filterChain.doFilter(request, response);
    }

    /**
     * Process a potentially valid token
     */
    private void processValidToken(String jwt, HttpServletRequest request) {
        try {
            String username = jwtConfig.extractUsername(jwt);

            if (username != null) {
                UserDetails userDetails = userDetailsService.loadUserByUsername(username);

                if (jwtConfig.validateToken(jwt, userDetails)) {
                    UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
                            userDetails, null, userDetails.getAuthorities());
                    auth.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(auth);
                    logger.debug("Authenticated user: {}", username);
                }
            }
        } catch (Exception e) {
            logger.warn("Token validation failed: {}", e.getMessage());
        }
    }

    private String getJwtFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader(AUTHORIZATION_HEADER);
        return StringUtils.hasText(bearerToken) && bearerToken.startsWith(BEARER_PREFIX) ?
                bearerToken.substring(BEARER_PREFIX.length()) : null;
    }
} 
