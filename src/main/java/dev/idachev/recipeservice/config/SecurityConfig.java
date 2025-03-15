package dev.idachev.recipeservice.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.cors.CorsConfigurationSource;

import java.time.LocalDateTime;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@Slf4j
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final CorsConfigurationSource corsConfigurationSource;

    public SecurityConfig(
            JwtAuthenticationFilter jwtAuthenticationFilter,
            CorsConfigurationSource corsConfigurationSource) {
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
        this.corsConfigurationSource = corsConfigurationSource;
        log.info("Security configuration initialized with JWT authentication");
    }

    private RequestMatcher apiMatcher() {

        return new AntPathRequestMatcher("/api/**");
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        log.info("Configuring security filter chain");

        http
                .csrf(csrf -> csrf
                        .ignoringRequestMatchers(apiMatcher())
                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                        .csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler()))

                .cors(cors -> cors.configurationSource(corsConfigurationSource))

                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/api-docs/**", "/swagger-ui/**", "/swagger-ui.html").permitAll()
                        .requestMatchers("/actuator/**").permitAll()
                        .requestMatchers("/error/**", "/static/**", "/css/**", "/js/**").permitAll()
                        .requestMatchers(HttpMethod.POST, "/api/v1/recipes/generate-meal").hasAnyRole("USER", "ADMIN")
                        .requestMatchers(HttpMethod.POST, "/api/v1/recipes/generate-meal-plan").hasAnyRole("USER", "ADMIN")
                        .requestMatchers(HttpMethod.POST, "/api/v1/recipes/generate-recipe").hasAnyRole("USER", "ADMIN")
                        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                        .anyRequest().authenticated()
                )

                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                .exceptionHandling(ex -> ex
                        // Handle access denied (403) errors
                        .accessDeniedHandler((
                                request,
                                response,
                                accessDeniedException) -> {

                            log.warn("Access denied for request to {}: {}",
                                    request.getRequestURI(), accessDeniedException.getMessage());

                            if (apiMatcher().matches(request)) {
                                response.setStatus(403);
                                response.setContentType(MediaType.APPLICATION_JSON_VALUE);

                                String jsonResponse = String.format(
                                        "{\"timestamp\":\"%s\",\"status\":%d,\"error\":\"Forbidden\",\"message\":\"Access denied: %s\",\"path\":\"%s\"}",
                                        LocalDateTime.now(),
                                        403,
                                        "You don't have permission to access this resource",
                                        request.getRequestURI()
                                );

                                response.getWriter().write(jsonResponse);
                            } else {

                                response.sendError(403, "Access Denied");
                            }
                        })
                        .authenticationEntryPoint((
                                request,
                                response,
                                authException) -> {
                            log.warn("Unauthorized request to path: {}, error: {}",
                                    request.getRequestURI(), authException.getMessage());

                            if (apiMatcher().matches(request)) {
                                response.setStatus(401);
                                response.setContentType(MediaType.APPLICATION_JSON_VALUE);

                                String jsonResponse = String.format(
                                        "{\"timestamp\":\"%s\",\"status\":%d,\"error\":\"Unauthorized\",\"message\":\"%s\",\"path\":\"%s\"}",
                                        LocalDateTime.now(),
                                        401,
                                        "Authentication required",
                                        request.getRequestURI()
                                );

                                response.getWriter().write(jsonResponse);
                            } else {
                                response.sendError(401, "Authentication required");
                            }
                        })
                )

                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
} 