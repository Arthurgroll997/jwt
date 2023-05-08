package com.arthurgroll.jwt.service;

import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
// import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.arthurgroll.jwt.dto.LoginInputDTO;
import com.arthurgroll.jwt.entity.Role;
import com.arthurgroll.jwt.entity.User;
import com.arthurgroll.jwt.repository.UserRepository;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

@Service
public class AuthService
{
    private final String key = "secret";
    private final String issuer = "test";
    private final Long duration = 60000L;

    // @Value("${jwt.key}")
    // private String key;

    // @Value("${jwt.token.issuer}")
    // private String issuer;

    // @Value("${jwt.token.duration}")
    // private Long duration;
    
    private final UserRepository userRepo;

    @Autowired
    public AuthService(UserRepository userRepo)
    {
        this.userRepo = userRepo;
    }

    private final ObjectMapper objMapper = new ObjectMapper().enable(DeserializationFeature.ACCEPT_SINGLE_VALUE_AS_ARRAY);
    private final Algorithm alg = Algorithm.HMAC256(key);
    private final JWTVerifier jwtVerifier = JWT.require(alg).withIssuer(issuer).build();

    public boolean login(LoginInputDTO input)
    {
        Optional<User> optUser = this.userRepo.findByUsername(input.username);

        return optUser.isEmpty() || !optUser.get().getPassword().equals(input.password);
    }

    public Optional<String> getJwtToken(LoginInputDTO input) throws JsonProcessingException, IllegalArgumentException, JWTCreationException
    {
        if (!this.userRepo.findByUsername(input.username).isPresent())
        {
            return Optional.empty();
        }

        User user = this.userRepo.findByUsername(input.username).get();

        return Optional.of(JWT.create()
            .withIssuer(issuer)
            .withClaim("roles", this.objMapper.writeValueAsString(user.getRoles()))
            .withSubject(input.username)
            .withIssuedAt(new Date())
            .withExpiresAt(new Date(System.currentTimeMillis() + duration))
            .withJWTId(UUID.randomUUID().toString())
            .withNotBefore(new Date(System.currentTimeMillis()))
            .sign(Algorithm.HMAC256(key)));
    }

    public boolean isTokenValid(String token)
    {
        try
        {
            this.jwtVerifier.verify(token);
            return true;
        }
        catch (JWTVerificationException e)
        {
            return false;
        }
    }

    public DecodedJWT getDecodedToken(String token)
    {
        return this.jwtVerifier.verify(token);
    }

    public boolean isAuthorized(String token, Set<Role> allowedRoles)
    {
        try
        {
            Set<String> roles =  this.objMapper.readValue(
                this.getDecodedToken(token).getClaim("roles").asString(), Set.class);

            return roles.stream()
                .anyMatch(r -> allowedRoles.contains(Role.valueOf(r)));
        }
        catch (Exception e)
        {
            return false;
        }
    }
}
