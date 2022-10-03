
package io.security.oauth2.springsecurityoauth2;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
public class DefaultSecurityConfig {

	@Bean
	public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {

		http.authorizeRequests(request -> request.anyRequest().authenticated());
		http.formLogin();

		return http.build();
	}

	@Bean
	public UserDetailsService userDetailsService(){
		UserDetails user = User.withUsername("user").password("{noop}1234").authorities("ROLE_USER").build();
		return new InMemoryUserDetailsManager(user);
	}

	@Bean
	public OAuth2AuthorizationService oAuth2AuthorizationService(){
		return new InMemoryOAuth2AuthorizationService();
	}

	@Bean
	public OAuth2AuthorizationConsentService oAuth2AuthorizationConsentService(){
		return new InMemoryOAuth2AuthorizationConsentService();
	}

	@Bean
	public CustomAuthenticationProvider customAuthenticationProvider(){
		return new CustomAuthenticationProvider();
	}

}