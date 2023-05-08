package com.arthurgroll.jwt.security;

import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import com.arthurgroll.jwt.entity.Role;
import com.arthurgroll.jwt.service.AuthService;

@Configuration
public class Security
{
    @Bean
    public PasswordEncoder passwordEncoder()
    {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, AuthService authService) throws Exception
    {
        http.csrf().disable().cors().disable().authorizeHttpRequests()
            .requestMatchers("/**")
            .permitAll()
            .and()
            .addFilterBefore(new JwtFilter(Map.of(
                "/api/users/*", Set.of(Role.USER, Role.ADMIN),
                "/api/restricted/**", Set.of(Role.ADMIN)),
                authService), BasicAuthenticationFilter.class);
        
        return http.build();
    }
}