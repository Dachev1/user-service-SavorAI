package dev.idachev.userservice.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * Configuration for Spring MVC, including view controllers and resource handlers
 */
@Configuration
public class WebMvcConfig implements WebMvcConfigurer {

    /**
     * Add simple automated controllers for URL to view mappings
     * @param registry The view controller registry
     */
    @Override
    public void addViewControllers(ViewControllerRegistry registry) {
        // Forward to home page for single page app (if needed)
        registry.addViewController("/").setViewName("redirect:/#/");
        
        // Add other view controllers as needed
    }
} 