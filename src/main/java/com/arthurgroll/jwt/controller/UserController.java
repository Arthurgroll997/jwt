package com.arthurgroll.jwt.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.arthurgroll.jwt.entity.User;
import com.arthurgroll.jwt.repository.UserRepository;

import jakarta.transaction.Transactional;

@RestController
@RequestMapping("/api/users")
public class UserController
{
    @Autowired
    private PasswordEncoder passEncoder;

    @Autowired
    private UserRepository userRepo;

    @PostMapping
    @Transactional
    public ResponseEntity<Long> registerUser(@RequestBody User user)
    {
        return new ResponseEntity<>(userRepo.save(new User(0L, user.getUsername(),
            passEncoder.encode(user.getPassword()), user.getRoles())).getId(), HttpStatus.CREATED);
    }
}
