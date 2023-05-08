package com.arthurgroll.jwt.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.arthurgroll.jwt.dto.LoginInputDTO;
import com.arthurgroll.jwt.service.AuthService;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.fasterxml.jackson.core.JsonProcessingException;

@RestController
@RequestMapping("/api/authentication")
public class AuthenticationController
{
    @Autowired
    private AuthService authService;
    
    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody LoginInputDTO input) throws JsonProcessingException, IllegalArgumentException, JWTCreationException
    {
        if (!this.authService.login(input))
            return new ResponseEntity<>("", HttpStatus.UNAUTHORIZED);

        return new ResponseEntity<>(this.authService.getJwtToken(input).get(), HttpStatus.OK);
    }
}
