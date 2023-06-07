package com.example.authserver;

import java.time.Duration;
import java.util.Set;
import java.util.stream.Collectors;

import javax.sql.DataSource;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
  @Bean
  @Order(1)
  public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)
      throws Exception {
    OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
    http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
        .oidc(Customizer.withDefaults()); // Enable OpenID Connect 1.0
    http
        // Redirect to the login page when not authenticated from the
        // authorization endpoint
        .exceptionHandling((exceptions) -> exceptions
            .defaultAuthenticationEntryPointFor(
                new LoginUrlAuthenticationEntryPoint("/login"),
                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)))
        // Accept access tokens for User Info and/or Client Registration
        .oauth2ResourceServer((resourceServer) -> resourceServer
            .jwt(Customizer.withDefaults()));

    return http.build();
  }

  // @Bean
  // @Order(1)
  // SecurityFilterChain asSecurityFilterChain(HttpSecurity http) throws Exception
  // {

  // OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

  // return http
  // .getConfigurer(OAuth2AuthorizationServerConfigurer.class)
  // .oidc(withDefaults())
  // .and()
  // .exceptionHandling(e -> e
  // .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")))
  // .oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt)
  // .build();
  // }

  @Bean
  @Order(2)
  public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
      throws Exception {
    http
        .authorizeHttpRequests((authorize) -> authorize
            .anyRequest().authenticated())
        // Form login handles the redirect to the login page from the
        // authorization server filter chain
        .formLogin(Customizer.withDefaults());

    return http.build();
  }

  // @Bean
  // public UserDetailsService userDetailsService() {
  // UserDetails userDetails = User.withDefaultPasswordEncoder()
  // .username("ken")
  // .password("pw")
  // .roles("user")
  // .build();

  // return new InMemoryUserDetailsManager(userDetails);
  // }

  @Bean
  JdbcOAuth2AuthorizationConsentService consentService(DataSource dataSource,
      RegisteredClientRepository clientRepository) {
    return new JdbcOAuth2AuthorizationConsentService(new JdbcTemplate(dataSource), clientRepository);
  }

  @Bean
  JdbcOAuth2AuthorizationService authorizationService(DataSource dataSource,
      RegisteredClientRepository clientRepository) {
    return new JdbcOAuth2AuthorizationService(new JdbcTemplate(dataSource), clientRepository);
  }

  @Bean
  JdbcRegisteredClientRepository registeredClientRepository(DataSource dataSource) {
    return new JdbcRegisteredClientRepository(new JdbcTemplate(dataSource));
  }

  // @Bean
  // public RegisteredClientRepository registeredClientRepository() {
  // RegisteredClient oidcClient =
  // RegisteredClient.withId(UUID.randomUUID().toString())
  // .clientId("client")
  // .clientSecret("{noop}secret")
  // .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
  // .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
  // .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
  // .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
  // .redirectUri("http://127.0.0.1:8082/login/oauth2/code/spring")
  // .postLogoutRedirectUri("http://127.0.0.1:8080/")
  // .scope(OidcScopes.OPENID)
  // .scope(OidcScopes.PROFILE)
  // .scope(OidcScopes.EMAIL)
  // .scope("user.read")
  // .scope("user.write")
  // .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
  // .build();

  // return new InMemoryRegisteredClientRepository(oidcClient);
  // }

  @Bean
  public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
    return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
  }

  @Bean
  public AuthorizationServerSettings authorizationServerSettings() {
    return AuthorizationServerSettings.builder().build();
  }

  @Bean
  TokenSettings tokenSettings() {
    return TokenSettings.builder()
        .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
        .accessTokenTimeToLive(Duration.ofDays(1))
        .build();
  }

  @Bean
  ClientSettings clientSettings() {
    return ClientSettings.builder()
        .requireProofKey(false)
        .requireAuthorizationConsent(false)
        .build();
  }

  // @Bean
  // OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
  // return context -> {
  // Authentication principal = context.getPrincipal();
  // if (context.getTokenType().getValue().equals("id_token")) {
  // context.getClaims().claim("Test", "Test Id Token");
  // }
  // if (context.getTokenType().getValue().equals("access_token")) {
  // context.getClaims().claim("Test", "Test Access Token");
  // Set<String> authorities = principal.getAuthorities().stream()
  // .map(GrantedAuthority::getAuthority).collect(Collectors.toSet());
  // context.getClaims().claim("authorities", authorities)
  // .claim("user", principal.getName());
  // }

  // };
  // }

}
