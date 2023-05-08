package com.arthurgroll.jwt.controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.arthurgroll.jwt.entity.User;
import com.arthurgroll.jwt.repository.UserRepository;

@RestController
@RequestMapping("/api/restricted")
public class DashboardController
{
    @Autowired
    private UserRepository userRepo;

    @GetMapping("/users")
    public ResponseEntity<List<User>> getUsers()
    {
        return new ResponseEntity<>(this.userRepo.findAll(), HttpStatus.OK);
    } 
}
