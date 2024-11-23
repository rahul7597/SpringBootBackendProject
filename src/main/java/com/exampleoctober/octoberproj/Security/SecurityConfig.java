// Yeh hai updated version aapke SecurityConfig class ke liye, jismein logger ka use kiya gaya hai:

package com.exampleoctober.octoberproj.Security;

// import java.util.Arrays;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
// import org.springframework.lang.NonNull;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
// import org.springframework.web.cors.CorsConfiguration;
// import org.springframework.web.cors.CorsConfigurationSource;

// import jakarta.servlet.http.HttpServletRequest;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private static final Logger logger = LoggerFactory.getLogger(SecurityConfig.class);

    @Bean
    public UserDetailsService userDetailsService() {
        logger.info("UserDetailsService bean created");
        return new CustomUserDetailsService();
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        logger.info("BCryptPasswordEncoder bean created");
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        logger.info("SecurityFilterChain bean created");
        http.csrf(csrf ->csrf.disable())
                .sessionManagement(sessionManagement -> sessionManagement.sessionCreationPolicy(org.springframework.security.config.http.SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/usersave", "/generate-otp", "/passwordSetByEmail", "/login", "/alluser","/otpwithpassword").permitAll()
                        .anyRequest().permitAll()
                // ) .cors(cors -> cors
                // .configurationSource(corsConfigurationSource())
    );
    
        logger.info("Security configuration completed");
        return http.build();
    }

//   @Bean
// public CorsConfigurationSource corsConfigurationSource() {
//     CorsConfiguration corsConfiguration = new CorsConfiguration();
//     corsConfiguration.setAllowedOrigins(Arrays.asList("*"));
//     corsConfiguration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
//     corsConfiguration.setAllowedHeaders(Arrays.asList("Content-Type", "Authorization"));
//     corsConfiguration.setExposedHeaders(Arrays.asList("Content-Type", "Authorization"));
//     corsConfiguration.setMaxAge(3600L);
//     return new CorsConfigurationSource() {
//         @Override
//         public CorsConfiguration getCorsConfiguration(@NonNull HttpServletRequest request) {
//             return corsConfiguration;
//         }
//     };
// }



    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        logger.info("AuthenticationManager bean created");
        return authenticationConfiguration.getAuthenticationManager();
    }
}


