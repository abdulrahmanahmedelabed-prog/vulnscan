package com.acme.shop;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

public class SecurityConfig {

    @Bean
    public SecurityFilterChain chain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/orders/search", "/actuator/health").permitAll()
                .requestMatchers("/api/orders/export").hasRole("ADMIN")
                .anyRequest().authenticated());
        return http.build();
    }
}
