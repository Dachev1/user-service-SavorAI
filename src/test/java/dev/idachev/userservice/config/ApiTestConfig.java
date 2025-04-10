package dev.idachev.userservice.config;

import dev.idachev.userservice.security.JwtAuthenticationFilter;
import dev.idachev.userservice.service.TokenBlacklistService;
import dev.idachev.userservice.service.UserDetailsService;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

/**
 * Test configuration for API tests
 * This configuration helps set up the necessary beans for WebMvcTest
 */
@TestConfiguration
@EnableWebSecurity
public class ApiTestConfig {

    @MockitoBean
    private JwtConfig jwtConfig;

    @MockitoBean
    private UserDetailsService userDetailsService;

    @MockitoBean
    private TokenBlacklistService tokenBlacklistService;

    /**
     * Configure security for API tests
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
                                                   JwtAuthenticationFilter jwtAuthFilter) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/v1/auth/**").permitAll()
                        .requestMatchers("/api/v1/verification/**").permitAll()
                        .requestMatchers("/api/v1/user/check-username").permitAll()
                        .requestMatchers("/api/v1/admin/**").hasRole("ADMIN")
                        .anyRequest().authenticated()
                )
                .sessionManagement(session -> session.sessionCreationPolicy(STATELESS))
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    /**
     * JWT filter for tests with mocked dependencies
     */
    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter() {
        return new JwtAuthenticationFilter(
                jwtConfig,
                userDetailsService,
                tokenBlacklistService
        );
    }
} 