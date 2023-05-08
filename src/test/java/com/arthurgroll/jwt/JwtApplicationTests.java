package com.arthurgroll.jwt;

import java.util.Set;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import com.arthurgroll.jwt.dto.LoginInputDTO;
import com.arthurgroll.jwt.entity.Role;
import com.arthurgroll.jwt.entity.User;
import com.arthurgroll.jwt.repository.UserRepository;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

@SpringBootTest
@AutoConfigureMockMvc
class JwtApplicationTests
{
	@Autowired
	private MockMvc mockMvc;

	@Autowired
	private UserRepository userRepo;

	@Autowired
	private PasswordEncoder passEncoder;

	private ObjectMapper objMapper = new ObjectMapper();

	private static LoginInputDTO admin = new LoginInputDTO("Admin", "TestPassAdmin");
	private static LoginInputDTO user = new LoginInputDTO("User", "TestPassUser");

	@BeforeEach
	void setup() throws JsonProcessingException, Exception
	{
		userRepo.deleteAll();

		User reqAdmin = new User(0L, admin.username, admin.password, Set.of(Role.ADMIN));
		User reqUser = new User(0L, user.username, user.password, Set.of(Role.USER));

		this.mockMvc.perform(post("/api/users")
			.contentType(MediaType.APPLICATION_JSON).content(this.objMapper.writeValueAsString(reqAdmin)))
			.andExpect(status().isCreated()).andReturn();
		
		this.mockMvc.perform(post("/api/users")
			.contentType(MediaType.APPLICATION_JSON).content(this.objMapper.writeValueAsString(reqUser)))
			.andExpect(status().isCreated()).andReturn();

		User admin = this.userRepo.findByUsername(reqAdmin.getUsername()).get();
		User user = this.userRepo.findByUsername(reqUser.getUsername()).get();
	}

	@Test
	void userRouteTestSuccess() throws JsonProcessingException, Exception
	{
		String token = this.mockMvc.perform(post("/api/authentication/login")
			.contentType(MediaType.APPLICATION_JSON).content(this.objMapper.writeValueAsString(user)))
			.andExpect(status().isOk()).andReturn().getResponse().getContentAsString();

		this.mockMvc.perform(get("/api/users/1").header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
			.andExpect(status().isOk());
	}

	@Test
	void userRouteTestFail() throws JsonProcessingException, Exception
	{
		this.mockMvc.perform(get("/api/users/1").header(HttpHeaders.AUTHORIZATION, "Bearer abcdefghijklmnopqrstuvwxyz"))
			.andExpect(status().isUnauthorized());
	}

	@Test
	void adminRouteTestSuccess() throws JsonProcessingException, Exception
	{
		String token = this.mockMvc.perform(post("/api/authentication/login")
			.contentType(MediaType.APPLICATION_JSON).content(this.objMapper.writeValueAsString(admin)))
			.andExpect(status().isOk()).andReturn().getResponse().getContentAsString();

		this.mockMvc.perform(get("/api/restricted/users").header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
			.andExpect(status().isOk());
	}

	@Test
	void adminRouteTestFail() throws JsonProcessingException, Exception
	{
		String token = this.mockMvc.perform(post("/api/authentication/login")
			.contentType(MediaType.APPLICATION_JSON).content(this.objMapper.writeValueAsString(user)))
			.andExpect(status().isOk()).andReturn().getResponse().getContentAsString();

		this.mockMvc.perform(get("/api/restricted/users").header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
			.andExpect(status().isUnauthorized());
	}
}
