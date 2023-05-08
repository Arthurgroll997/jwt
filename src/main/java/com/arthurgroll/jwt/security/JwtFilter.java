package com.arthurgroll.jwt.security;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.Map.Entry;
import java.util.function.Consumer;
import java.util.function.Function;

import javax.security.sasl.AuthenticationException;

import org.springframework.http.HttpStatus;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import com.arthurgroll.jwt.entity.Role;
import com.arthurgroll.jwt.service.AuthService;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class JwtFilter extends OncePerRequestFilter
{
    private final AuthService authService;
    private final Map<String, Set<Role>> routesAndRoles;

    public JwtFilter(Map<String, Set<Role>> routesAndRoles, AuthService authService)
    {
        this.routesAndRoles = routesAndRoles;
        this.authService = authService;
    }

    private Optional<Set<Role>> getMatchingRoles(HttpServletRequest req)
    {
        for (Entry<String, Set<Role>> rr : this.routesAndRoles.entrySet())
            if (new AntPathRequestMatcher(rr.getKey()).matches(req))
                return Optional.of(rr.getValue());

        return Optional.empty();
    }

    private boolean matchesUrl(HttpServletRequest req)
    {
        return this.getMatchingRoles(req).isPresent();
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
        throws ServletException, IOException
    {
        String url = request.getRequestURI();
        
        if (!this.matchesUrl(request))
        {
            filterChain.doFilter(request, response);
            return;
        }
        
        String token = request.getHeader("Authorization");

        if (token == null || token.length() < 15)
            throw new AuthenticationException();

        token = token.split("Bearer ")[1];

        this.logger.info("TOKEN RECEIVED: " + token);

        if (!this.authService.isTokenValid(token) ||
            !this.authService.isAuthorized(token, this.getMatchingRoles(request).get()))
        {
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
            return;
        }
    }
}
