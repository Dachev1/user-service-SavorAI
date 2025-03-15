package dev.idachev.recipeservice.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class OpenApiConfig {

    @Bean
    public OpenAPI customOpenAPI() {
        final String securitySchemeName = "bearerAuth";
        
        return new OpenAPI()
                .info(new Info()
                    .title("SavorAI Recipe API")
                    .description("API for recipe generation using OpenAI integration")
                    .version("1.0")
                    .contact(new Contact()
                        .name("SavorAI Team")
                        .email("appsavorai@gmail.com")
                        .url("https://savorai.example.com"))
                    .license(new License()
                        .name("MIT License")
                        .url("https://opensource.org/licenses/MIT")))
                .addSecurityItem(new SecurityRequirement().addList(securitySchemeName))
                .components(new Components()
                    .addSecuritySchemes(securitySchemeName, new SecurityScheme()
                        .name(securitySchemeName)
                        .type(SecurityScheme.Type.HTTP)
                        .scheme("bearer")
                        .bearerFormat("JWT")
                        .description("JWT Auth header using Bearer scheme")));
    }
} 