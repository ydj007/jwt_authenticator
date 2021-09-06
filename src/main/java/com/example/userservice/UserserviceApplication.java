package com.example.userservice;

import com.example.userservice.domain.Role;
import com.example.userservice.domain.User;
import com.example.userservice.service.UserService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;

@SpringBootApplication
public class UserserviceApplication {

	public static void main(String[] args) {
		SpringApplication.run(UserserviceApplication.class, args);
	}

	@Bean
	BCryptPasswordEncoder bCryptPasswordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}


	@Bean
	CommandLineRunner run(UserService userService, PasswordEncoder passwordEncoder){
		return args -> {
			userService.saveRole(new Role(null,"ROLE_USER"));
			userService.saveRole(new Role(null,"ROLE_MANAGER"));
			userService.saveRole(new Role(null,"ROLE_ADMIN"));
			userService.saveRole(new Role(null,"ROLE_SUPERADMIN"));

			userService.saveUser(new User(null,"홍길동","honghero","1234",new ArrayList<>()));
			userService.saveUser(new User(null,"이순신","generalyi","1234",new ArrayList<>()));
			userService.saveUser(new User(null,"임꺽정","greatlim","1234",new ArrayList<>()));
			userService.saveUser(new User(null,"전우치","ghostjun","1234",new ArrayList<>()));

			userService.addRoleToUser("honghero","ROLE_USER");
			userService.addRoleToUser("generalyi","ROLE_USER");
			userService.addRoleToUser("greatlim","ROLE_USER");
			userService.addRoleToUser("ghostjun","ROLE_USER");
			userService.addRoleToUser("generalyi","ROLE_MANAGER");
			userService.addRoleToUser("greatlim","ROLE_ADMIN");
			userService.addRoleToUser("ghostjun","ROLE_SUPERADMIN");
		};
	}


}
