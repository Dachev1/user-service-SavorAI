package dev.idachev.userservice.config;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.cache.concurrent.ConcurrentMapCacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Profile;

import java.util.List;

@TestConfiguration
@EnableCaching
@Profile("test")
public class TestCacheConfig {

    /**
     * Configure a test cache manager for testing
     */
    @Bean
    @Primary
    public CacheManager cacheManager() {
        ConcurrentMapCacheManager cacheManager = new ConcurrentMapCacheManager();
        cacheManager.setCacheNames(List.of("users", "profiles", "userDetails"));
        return cacheManager;
    }
} 