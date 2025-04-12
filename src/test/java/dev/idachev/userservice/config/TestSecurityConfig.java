package dev.idachev.userservice.config;

import dev.idachev.userservice.security.JwtAuthenticationFilter;
import dev.idachev.userservice.service.TokenBlacklistService;
import dev.idachev.userservice.service.UserDetailsService;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import static org.mockito.Mockito.mock;

/**
 * Test configuration for API tests
 */
@TestConfiguration
@EnableWebSecurity
public class TestSecurityConfig {

    @Bean
    @Primary
    public JwtConfig jwtConfig() {
        return new JwtConfig();
    }

    @Bean
    @Primary
    public UserDetailsService userDetailsService() {
        return mock(UserDetailsService.class);
    }
    
    @Bean
    @Primary
    public JwtAuthenticationFilter jwtAuthenticationFilter(
            JwtConfig jwtConfig,
            UserDetailsService userDetailsService,
            TokenBlacklistService tokenBlacklistService) {
        return new JwtAuthenticationFilter(jwtConfig, userDetailsService, tokenBlacklistService);
    }
    
    @Bean
    @Primary
    public TokenBlacklistService tokenBlacklistService() {
        return mock(TokenBlacklistService.class);
    }
    
    @Bean
    @Primary
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
    
    @Bean
    @Primary
    public AuthenticationManager authenticationManager() {
        return mock(AuthenticationManager.class);
    }
    
    @Bean
    @Primary
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf(AbstractHttpConfigurer::disable)
            .cors(AbstractHttpConfigurer::disable)
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth.anyRequest().permitAll());
        
        return http.build();
    }
} 