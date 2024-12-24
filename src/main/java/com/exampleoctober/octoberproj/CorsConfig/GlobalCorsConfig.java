package com.exampleoctober.octoberproj.CorsConfig;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class GlobalCorsConfig {

    @Bean
    public WebMvcConfigurer corsConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(@SuppressWarnings("null") CorsRegistry registry) {
                registry.addMapping("/**") // Allow all endpoints
                        .allowedOrigins("https://e-commerce-project-lovat-two.vercel.app", "https://ecommerce-goap.vercel.app") // Allow specific origins (update as needed)
                        .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS") // Allow specific HTTP methods
                        .allowedHeaders("Authorization", "Content-Type") // Allow specific headers
                        .exposedHeaders("Authorization") // Expose specific headers to the client
                        .allowCredentials(true) // Allow cookies/auth headers in cross-origin requests
                        .maxAge(100 * 365 * 24 * 60 * 60); // Cache preflight response for 100 Years
            }
        };
    }
}
