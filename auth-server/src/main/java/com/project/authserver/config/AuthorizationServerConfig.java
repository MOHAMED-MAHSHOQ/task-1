// auth-server/src/main/java/com/project/authserver/config/AuthorizationServerConfig.java

package com.project.authserver.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.project.authserver.entity.User;
import com.project.authserver.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

// ✅ CORRECT import — note the full path:
// org.springframework.security.oauth2.server.authorization.config.annotation.web.CONFIGURATION
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;

import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.UUID;

/*
 * WHY THE IMPORT WAS WRONG:
 *
 * Your old import:
 *   org.springframework.security.config.annotation.web.configuration
 *   ↑ This is the GENERAL Spring Security config package
 *   ↑ OAuth2AuthorizationServerConfiguration does NOT live here
 *
 * Correct import:
 *   org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration
 *   ↑ This is the OAUTH2 AUTHORIZATION SERVER specific package
 *   ↑ This is where OAuth2AuthorizationServerConfiguration lives
 *
 * Simple memory trick:
 *   The class starts with "OAuth2" → its package also starts with "oauth2.server.authorization"
 */

@Configuration
@RequiredArgsConstructor
public class AuthorizationServerConfig {

    private final UserService userService;

    private static KeyPair generateRsaKey() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            return keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to generate RSA key pair", ex);
        }
    }

    /*
     * RegisteredClientRepository — the list of apps allowed to request tokens.
     *
     * We have ONE client: "react-app"
     *
     * PUBLIC client = no secret (React runs in browser, secrets aren't safe in JS).
     * PKCE = the security mechanism that replaces the secret for public clients.
     */
    @Bean
    public RegisteredClientRepository registeredClientRepository() {

        RegisteredClient reactApp = RegisteredClient
                .withId(UUID.randomUUID().toString())
                .clientId("react-app")
                // NONE = no secret. React uses PKCE instead.
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("http://localhost:5173/callback")
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .scope(OidcScopes.EMAIL)
                .clientSettings(ClientSettings.builder()
                        // requireProofKey = ENFORCE PKCE on every request
                        .requireProofKey(true)
                        // false = no "Allow/Deny" consent screen
                        .requireAuthorizationConsent(false)
                        .build())
                .tokenSettings(TokenSettings.builder()
                        // Short access token = smaller attack window if stolen
                        .accessTokenTimeToLive(Duration.ofMinutes(15))
                        // Refresh token lives longer so user stays "logged in"
                        .refreshTokenTimeToLive(Duration.ofDays(1))
                        .build())
                .build();

        return new InMemoryRegisteredClientRepository(reactApp);
    }

    /*
     * JWKSource — provides the RSA key pair used to SIGN JWT tokens.
     *
     * Auth Server signs with PRIVATE key (only it knows).
     * Everyone verifies with PUBLIC key (available at /.well-known/jwks.json).
     *
     * ⚠️ New key pair generated on every server restart.
     * Existing tokens become invalid after restart. Fine for development.
     */
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();

        return new ImmutableJWKSet<>(new JWKSet(rsaKey));
    }

    /*
     * JwtDecoder — lets the Auth Server itself decode tokens it issued.
     * Needed internally (e.g., /userinfo endpoint reads the access token).
     */
    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    /*
     * AuthorizationServerSettings — sets the issuer URL.
     * "iss" claim in every JWT = "http://localhost:9000"
     * Service B checks this to verify tokens came from OUR server.
     */
    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
                .issuer("http://localhost:9000")
                .build();
    }

    /*
     * tokenCustomizer — adds extra claims to every JWT before it's sent.
     *
     * Default JWT only has: sub, iss, iat, exp, scope
     * After this customizer:  sub, iss, iat, exp, scope, EMAIL, ROLE, NAME
     *
     * Why add email/role/name?
     * → Service B reads role from JWT without making a DB call.
     * → React can show user's name without an extra API call.
     */
    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
        return (context) -> {
            // context.getPrincipal().getName() = the email the user logged in with
            String email = context.getPrincipal().getName();
            User user = userService.findByEmail(email);

            // Add our custom claims into the JWT payload
            context.getClaims()
                    .claim("email", user.getEmail())
                    .claim("role", user.getRole())
                    .claim("name", user.getName());
        };
    }
}