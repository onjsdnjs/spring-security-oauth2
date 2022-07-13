package io.security.oauth2.springsecurityoauth2.dto;

import lombok.Data;

@Data
public class LoginDto {
	private String username;
	private String password;
}
