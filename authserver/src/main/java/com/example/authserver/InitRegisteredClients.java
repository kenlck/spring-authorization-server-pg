package com.example.authserver;

import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.stereotype.Component;

// @Component
public class InitRegisteredClients implements ApplicationRunner {
	private final RegisteredClientRepository repository;

	public InitRegisteredClients(RegisteredClientRepository repository) {
		this.repository = repository;
	}

	@Override
	public void run(ApplicationArguments args) throws Exception {

		RegisteredClient.Builder registration = RegisteredClient.withId("spring")
				.clientId("client")
				// plaintext is secret It is encoded with BCrypt from EncodedSecretTests
				// do not include secrets in the source code because bad actors can get access
				// to your secrets
				.clientSecret("{bcrypt}$2a$10$jdJGhzsiIqYFpjJiYWMl/eKDOd8vdyQis2aynmFN0dgJ53XvpzzwC")
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantTypes(types -> {
					types.add(AuthorizationGrantType.AUTHORIZATION_CODE);
					types.add(AuthorizationGrantType.CLIENT_CREDENTIALS);
					types.add(AuthorizationGrantType.REFRESH_TOKEN);
				})
				.redirectUri("http://127.0.0.1:8080/login/oauth2/code/spring")
				.redirectUri("http://127.0.0.1:3000/api/auth/callback/spring")
				.scopes(scopes -> {
					scopes.add("openid");
					scopes.add("profile");
					scopes.add("email");
					scopes.add("phone");
					scopes.add("address");
					scopes.add("keys.write");
					scopes.add("user.read");
					scopes.add("user.write");
				})
				.clientSettings(ClientSettings.builder()
						.requireAuthorizationConsent(false)
						.build());
		repository.save(registration.build());
	}
}
