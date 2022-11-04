package com.security.oauth2.server.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.security.oauth2.server.config.custom.CustomOAuth2AuthorizationCodeAuthenticationProvider;
import com.security.oauth2.server.config.custom.CustomOAuth2ConfigurerUtils;
import com.security.oauth2.server.config.custom.CustomPublicClientAuthenticationConverter;
import com.security.oauth2.server.config.custom.CustomPublicClientAuthenticationProvider;
import com.security.oauth2.server.util.Cache;
import com.security.oauth2.server.util.OAuthRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.ClientSecretAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.JwtClientAssertionAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientCredentialsAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2RefreshTokenAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.config.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.web.authentication.ClientSecretBasicAuthenticationConverter;
import org.springframework.security.oauth2.server.authorization.web.authentication.ClientSecretPostAuthenticationConverter;
import org.springframework.security.oauth2.server.authorization.web.authentication.DelegatingAuthenticationConverter;
import org.springframework.security.oauth2.server.authorization.web.authentication.JwtClientAssertionAuthenticationConverter;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

@Configuration(proxyBeanMethods = false)
public class AuthorizationServerConfig extends OAuth2AuthorizationServerConfiguration {

    private static PasswordEncoder passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfigurer<HttpSecurity> authorizationServerConfigurer =
                new OAuth2AuthorizationServerConfigurer<>();
        RequestMatcher endpointsMatcher = authorizationServerConfigurer
                .getEndpointsMatcher();
        OAuth2AuthorizationService authorizationService = CustomOAuth2ConfigurerUtils.getAuthorizationService(http);
        RegisteredClientRepository registeredClientRepository = CustomOAuth2ConfigurerUtils.getRegisteredClientRepository(http);

        http
                .requestMatcher(endpointsMatcher)
                .authorizeRequests(authorizeRequests -> authorizeRequests.anyRequest().authenticated())
                .csrf(csrf -> csrf.ignoringRequestMatchers(endpointsMatcher))
                .apply(authorizationServerConfigurer);

        authorizationServerConfigurer
                .authorizationEndpoint(authorizationEndpoint ->
                        authorizationEndpoint.authorizationResponseHandler(this::authorizationResponseHandler)
                );

        //this is useful for populating refresh token in the oauth2/token end-point with "code" grant_type with public clients
        authorizationServerConfigurer.tokenEndpoint(tokenEndpoint ->
                createTokenEndpointAuthenticationProviders(http, authorizationService).forEach(tokenEndpoint::authenticationProvider));

        //this is useful for generating tokens using refresh token with public clients
        authorizationServerConfigurer.clientAuthentication(clientAuth ->
        {
            clientAuth.authenticationConverter(getDelegatingAuthenticationConverter());
            getClientAuthenticationProviders(http, registeredClientRepository, authorizationService).forEach(clientAuth::authenticationProvider);
        });

        return http.cors().and().formLogin().loginPage("/login").permitAll().and().build();
    }

    private static DelegatingAuthenticationConverter getDelegatingAuthenticationConverter() {
        return new DelegatingAuthenticationConverter(
                Arrays.asList(
                        new JwtClientAssertionAuthenticationConverter(),
                        new ClientSecretBasicAuthenticationConverter(),
                        new ClientSecretPostAuthenticationConverter(),
                        new CustomPublicClientAuthenticationConverter()));
    }

    //copied from OAuth2TokenEndpointConfigurer#createDefaultAuthenticationProviders
    private <B extends HttpSecurityBuilder<B>> List<AuthenticationProvider> createTokenEndpointAuthenticationProviders(B builder, OAuth2AuthorizationService authorizationService) {
        List<AuthenticationProvider> authenticationProviders = new ArrayList<>();

        OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator = CustomOAuth2ConfigurerUtils.getTokenGenerator(builder);

        //used our custom provider
        CustomOAuth2AuthorizationCodeAuthenticationProvider authorizationCodeAuthenticationProvider =
                new CustomOAuth2AuthorizationCodeAuthenticationProvider(authorizationService, tokenGenerator);
        authenticationProviders.add(authorizationCodeAuthenticationProvider);

        OAuth2RefreshTokenAuthenticationProvider refreshTokenAuthenticationProvider =
                new OAuth2RefreshTokenAuthenticationProvider(authorizationService, tokenGenerator);
        authenticationProviders.add(refreshTokenAuthenticationProvider);

        OAuth2ClientCredentialsAuthenticationProvider clientCredentialsAuthenticationProvider =
                new OAuth2ClientCredentialsAuthenticationProvider(authorizationService, tokenGenerator);
        authenticationProviders.add(clientCredentialsAuthenticationProvider);

        return authenticationProviders;
    }

    //copied from OAuth2ClientAuthenticationConfigurer#createDefaultAuthenticationProviders
    private <B extends HttpSecurityBuilder<B>> List<AuthenticationProvider> getClientAuthenticationProviders(B builder,
                                                                                                             RegisteredClientRepository registeredClientRepository,
                                                                                                             OAuth2AuthorizationService authorizationService) {
        List<AuthenticationProvider> authenticationProviders = new ArrayList<>();

        JwtClientAssertionAuthenticationProvider jwtClientAssertionAuthenticationProvider =
                new JwtClientAssertionAuthenticationProvider(registeredClientRepository, authorizationService);
        authenticationProviders.add(jwtClientAssertionAuthenticationProvider);

        ClientSecretAuthenticationProvider clientSecretAuthenticationProvider =
                new ClientSecretAuthenticationProvider(registeredClientRepository, authorizationService);
        PasswordEncoder passwordEncoder = CustomOAuth2ConfigurerUtils.getOptionalBean(builder, PasswordEncoder.class);
        if (passwordEncoder != null) {
            clientSecretAuthenticationProvider.setPasswordEncoder(passwordEncoder);
        }
        authenticationProviders.add(clientSecretAuthenticationProvider);

        //used our custom provider
        CustomPublicClientAuthenticationProvider publicClientAuthenticationProvider =
                new CustomPublicClientAuthenticationProvider(registeredClientRepository, authorizationService);
        authenticationProviders.add(publicClientAuthenticationProvider);

        return authenticationProviders;
    }

    /*@Bean
    public RegisteredClientRepository registeredClientRepository() {
        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("articles-client")
                .clientSecret("{noop}secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("http://127.0.0.1:8080/login/oauth2/code/articles-client-oidc")
                .redirectUri("http://127.0.0.1:8080/authorized")
                .scope(OidcScopes.OPENID)
                .scope("articles.read")
                .build();

        return new InMemoryRegisteredClientRepository(registeredClient);
    }*/

    @Bean
    @Profile("pkce")
    public RegisteredClientRepository registeredClientRepositoryPkce() {
        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("articles-client")
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(false)
                        .requireProofKey(true)
                        .build())
                .tokenSettings(
                        TokenSettings.builder()
                                .refreshTokenTimeToLive(Duration.ofSeconds(60 * 300))
                                .accessTokenTimeToLive(Duration.ofSeconds(60 * 10))
                                .reuseRefreshTokens(false)
                                .build())
                //todo make it configurable
                .redirectUri("http://127.0.0.1:8090/authorized")
                .scope(OidcScopes.OPENID)
                .build();

        return new InMemoryRegisteredClientRepository(registeredClient);
    }

    @Bean
    @Profile("!pkce")
    public RegisteredClientRepository registeredClientRepository() {
        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("articles-client")
//                .clientSecret("{noop}secret")
                .clientSecret(passwordEncoder.encode("secret"))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
//                .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .tokenSettings(
                        TokenSettings.builder()
                                .refreshTokenTimeToLive(Duration.ofSeconds(60 * 300))
                                .accessTokenTimeToLive(Duration.ofSeconds(60 * 10))
                                .reuseRefreshTokens(false)
                                .build())
                .redirectUri("http://127.0.0.1:8090/authorized")
                .scope(OidcScopes.OPENID)
                .build();

        return new InMemoryRegisteredClientRepository(registeredClient);
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        RSAKey rsaKey = generateRsa();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
    }

    private static RSAKey generateRsa() {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        return new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
    }

    private static KeyPair generateRsaKey() {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return keyPair;
    }

    @Bean
    public ProviderSettings providerSettings() {
        return ProviderSettings.builder()
                .issuer("http://127.0.0.1:8081")
                .build();
    }

    private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    private void authorizationResponseHandler(HttpServletRequest request, HttpServletResponse response,
                                              Authentication authentication) throws IOException {
        OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication =
                (OAuth2AuthorizationCodeRequestAuthenticationToken) authentication;
        OAuthRequest oAuthRequest = new OAuthRequest();
        oAuthRequest.setRedirectUri(authorizationCodeRequestAuthentication.getRedirectUri());
        oAuthRequest.setCode(authorizationCodeRequestAuthentication.getAuthorizationCode().getTokenValue());
        oAuthRequest.setState(authorizationCodeRequestAuthentication.getState());

        String uuId = UUID.randomUUID().toString();
        Cache.addCache(uuId, oAuthRequest);


        Set<GrantedAuthority> authorities = new HashSet<>();
        authorities.add(new SimpleGrantedAuthority("PRE_AUTH"));

        Authentication reAuth = new UsernamePasswordAuthenticationToken("admin",
//                "password"
                passwordEncoder.encode("password")
                , authorities);

        SecurityContextHolder.getContext().setAuthentication(reAuth);

        String mfaUrl = "http://127.0.0.1:8081/mfa?uuid=" + uuId;
        this.redirectStrategy.sendRedirect(request, response, mfaUrl);
    }

}
