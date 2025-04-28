package dev.idachev.userservice.security;

import dev.idachev.userservice.config.JwtConfig;
import dev.idachev.userservice.model.User;
import dev.idachev.userservice.service.TokenBlacklistService;
import dev.idachev.userservice.service.UserDetailsService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
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
import org.springframework.security.core.GrantedAuthority;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

/**
 * JWT Authentication Filter
 */
@Component
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final String CONTENT_TYPE_JSON = "application/json";
    private static final String ERROR_RESPONSE = "{\"error\":\"Unauthorized\",\"message\":\"Token is no longer valid\",\"action\":\"Please log out and log in again to continue.\"}";

    private static final List<String> PUBLIC_PATHS = Arrays.asList(
            "/api/v1/auth/signin", "/api/v1/auth/signup", "/api/v1/auth/refresh-token", 
            "/api/v1/auth/check-status", "/api/v1/verification/status", 
            "/api/v1/verification/resend", "/api/v1/verification/verify/**", 
            "/api/v1/user/check-username", "/api/v1/contact/submit", 
            "/swagger-ui/**", "/api-docs/**", "/v3/api-docs/**",
            "/css/**", "/js/**", "/images/**", "/favicon.ico"
    );

    private final JwtConfig jwtConfig;
    private final UserDetailsService userDetailsService;
    private final TokenBlacklistService tokenBlacklistService;
    private final AntPathMatcher pathMatcher = new AntPathMatcher();

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
        String path = request.getRequestURI();
        return PUBLIC_PATHS.stream().anyMatch(pattern -> pathMatcher.match(pattern, path));
    }

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain) throws ServletException, IOException {

        try {
            String token = extractJwtFromRequest(request);

            if (StringUtils.hasText(token)) {
                if (tokenBlacklistService.isJwtBlacklisted(token)) {
                    rejectBlacklistedToken(response);
                    return;
                }

                if (SecurityContextHolder.getContext().getAuthentication() == null) {
                    authenticateToken(token, request); 
                }
            }
        } catch (ExpiredJwtException e) {
            // Token expired, continue to filter chain
        } catch (Exception e) {
            log.error("JWT auth error: {}", e.getMessage());
        }

        filterChain.doFilter(request, response);
    }

    private String extractJwtFromRequest(HttpServletRequest request) {
        String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        return header != null && header.startsWith("Bearer ") ? header.substring(7) : null;
    }

    private void rejectBlacklistedToken(HttpServletResponse response) throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(CONTENT_TYPE_JSON);
        response.getWriter().write(ERROR_RESPONSE);
    }

    private void authenticateToken(String token, HttpServletRequest request) {
        if (token == null || token.isBlank()) return;

        try {
            Claims claims = jwtConfig.extractAllClaims(token);
            
            if (isServiceToken(token, claims)) {
                authenticateServiceToken(token, claims, request);
            } else {
                authenticateUserToken(token, claims, request);
            }
        } catch (Exception e) {
            log.debug("Token authentication failed: {}", e.getMessage());
        }
    }
    
    private boolean isServiceToken(String token, Claims claims) {
        return "service".equals(claims.get("type", String.class)) || 
               jwtConfig.extractRoles(token).stream()
                   .anyMatch(role -> role.getAuthority().equals("ROLE_SERVICE"));
    }
    
    private void authenticateServiceToken(String token, Claims claims, HttpServletRequest request) {
        String serviceName = claims.getSubject();
        List<GrantedAuthority> roles = jwtConfig.extractRoles(token);
        
        if (!jwtConfig.validateServiceTokenClaims(claims)) {
            return;
        }
        
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
                serviceName, null, roles);
        auth.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        SecurityContextHolder.getContext().setAuthentication(auth);
    }
    
    private void authenticateUserToken(String token, Claims claims, HttpServletRequest request) {
        UUID userId = jwtConfig.extractUserIdFromClaims(claims);
        if (userId == null) return;
        
        if (tokenBlacklistService.isUserInvalidated(userId.toString())) {
            log.warn("Blocked request with invalidated token: {}", userId);
            return;
        }
        
        try {
            UserDetails userDetails = userDetailsService.loadUserById(userId);
            
            // Check if user is banned but don't immediately reject
            // This allows the request to continue but the ban status will be visible in the UI
            if (userDetails instanceof UserPrincipal userPrincipal) {
                User user = userPrincipal.user();
                if (user.isBanned()) {
                    log.debug("Authenticated banned user: {}", user.getUsername());
                }
            }
            
            if (jwtConfig.validateToken(token, userDetails)) {
                UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities());
                auth.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(auth);
            }
        } catch (UsernameNotFoundException e) {
            // User not found in database
        }
    }
}
