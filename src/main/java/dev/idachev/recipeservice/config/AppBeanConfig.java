package dev.idachev.recipeservice.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

@Configuration
@Slf4j
public class AppBeanConfig {

    @Value("${cors.allowed-origins}") private String allowedOrigins;
    @Value("${cors.allowed-methods}") private String allowedMethods;
    @Value("${cors.allowed-headers}") private String allowedHeaders;
    @Value("${cors.allow-credentials}") private boolean allowCredentials;

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {

        log.info("Configuring CORS with origins: {}", allowedOrigins);
        
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(Arrays.asList(allowedOrigins.split(",")));
        config.setAllowedMethods(Arrays.asList(allowedMethods.split(",")));
        config.setAllowedHeaders(Arrays.asList(allowedHeaders.split(",")));
        config.setAllowCredentials(allowCredentials);
        config.setMaxAge(3600L);
        config.setExposedHeaders(List.of("Authorization", "Content-Type"));
        
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }

    @Bean
    public AntPathMatcher antPathMatcher() {
        return new AntPathMatcher();
    }

    @Bean
    public ConcurrentHashMap<String, Long> stringLongConcurrentHashMap() {
        return new ConcurrentHashMap<>();
    }
}
