package dev.idachev.userservice.config;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.cache.CacheManager;
import org.springframework.cache.concurrent.ConcurrentMapCacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Primary;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.thymeleaf.spring6.SpringTemplateEngine;

import static org.mockito.Mockito.mock;

@TestConfiguration
@ComponentScan(basePackages = {"dev.idachev.userservice.service"})
public class TestConfig {
    
    @Bean
    @Primary
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
    
    @Bean
    @Primary
    public JavaMailSender javaMailSender() {
        return mock(JavaMailSender.class);
    }
    
    @Bean
    @Primary
    public SpringTemplateEngine templateEngine() {
        return mock(SpringTemplateEngine.class);
    }
    
    @Bean
    @Primary
    public AuthenticationManager authenticationManager() {
        return mock(AuthenticationManager.class);
    }
    
    @Bean
    @Primary
    public CacheManager cacheManager() {
        ConcurrentMapCacheManager cacheManager = new ConcurrentMapCacheManager();
        cacheManager.setCacheNames(java.util.Arrays.asList("users", "profiles", "userDetails"));
        return cacheManager;
    }
} 