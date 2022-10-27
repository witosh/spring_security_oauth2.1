package com.github.witosh.authorization.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class WebSecurityConfig {
	
	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
		return httpSecurity.formLogin()
				.and().authorizeRequests().anyRequest().authenticated()
				.and().build();
	}
		
	@Bean
	public UserDetailsService userDetailsService() {
		UserDetails user = User
				.withUsername("bill")
				.password("12345")
				.authorities("read")
				.build();
		InMemoryUserDetailsManager detailsManager = new InMemoryUserDetailsManager();
		detailsManager.createUser(user);
		return detailsManager;
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return NoOpPasswordEncoder.getInstance();
	}
}
