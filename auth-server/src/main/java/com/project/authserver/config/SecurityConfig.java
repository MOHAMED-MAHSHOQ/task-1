// auth-server/src/main/java/com/project/authserver/config/SecurityConfig.java

package com.project.authserver.config;

import com.project.authserver.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

/**
 * SecurityConfig — defines all HTTP security rules for the Auth Server.
 *
 * WHY TWO SecurityFilterChains?
 *
 * A SecurityFilterChain = a set of rules for a group of URLs.
 * Spring checks them in @Order order (1 first, 2 second).
 *
 * Chain 1 (Order 1): OAuth2 endpoints only
 *   → /oauth2/authorize, /oauth2/token, /.well-known/jwks.json, etc.
 *   → Special rules from Spring Authorization Server
 *
 * Chain 2 (Order 2): Everything else
 *   → /login, /admin/**, and any other URLs
 *   → Standard Spring Security rules
 *
 * They must be SEPARATE chains because the OAuth2 endpoints need
 * very specific security filters that would conflict with regular endpoints.
 */
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final UserService userService;

    /**
     * CHAIN 1 — OAuth2 Authorization Server endpoints.
     *
     * This chain ONLY handles OAuth2/OIDC protocol URLs:
     *   /oauth2/authorize
     *   /oauth2/token
     *   /oauth2/jwks  (same as /.well-known/jwks.json)
     *   /oauth2/revoke
     *   /oauth2/introspect
     *   /userinfo
     *   /.well-known/openid-configuration
     *
     * How it works step by step:
     *
     * Step 1: OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http)
     *   This is the magic line. It:
     *   - Sets the securityMatcher to ONLY match OAuth2 endpoints
     *   - Applies all the default OAuth2 Authorization Server security filters
     *   - Configures PKCE validation, token endpoint, authorization endpoint
     *   Think of it as: "apply all the OAuth2 rules from Spring's recipe"
     *
     * Step 2: http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
     *   Gets the configurer that was just applied so we can customize it.
     *   .oidc(withDefaults()) → enables OpenID Connect 1.0 endpoints
     *   This adds /userinfo and /.well-known/openid-configuration
     *
     * Step 3: exceptionHandling
     *   If someone tries to access /oauth2/authorize without being logged in,
     *   redirect them to /login page first.
     */
    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(
            HttpSecurity http) throws Exception {

        // Apply ALL default OAuth2 Authorization Server security rules
        // This single line sets up the entire OAuth2 protocol machinery
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        // Get the configurer so we can add OIDC support on top
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                /*
                 * .oidc(Customizer.withDefaults()) enables OpenID Connect 1.0.
                 * Without this, we'd have OAuth2 but NOT OIDC.
                 * OIDC adds:
                 *   - id_token in token response (contains user identity info)
                 *   - /userinfo endpoint (get user info from access token)
                 *   - /.well-known/openid-configuration discovery endpoint
                 */
                .oidc(Customizer.withDefaults());

        http
                /*
                 * exceptionHandling — what to do when a request is rejected.
                 *
                 * LoginUrlAuthenticationEntryPoint("/login") means:
                 * "If a user tries to access a protected OAuth2 endpoint
                 *  but isn't logged in, redirect them to /login"
                 *
                 * This is the redirect that happens when React sends
                 * the user to /oauth2/authorize — the Auth Server
                 * redirects to /login first, user logs in, then Auth Server
                 * redirects back to React /callback with the code.
                 */
                .exceptionHandling(exceptions -> exceptions
                        .authenticationEntryPoint(
                                new LoginUrlAuthenticationEntryPoint("/login"))
                );

        return http.build();
    }

    /**
     * CHAIN 2 — All other endpoints (login page, admin API, etc.)
     *
     * This chain handles everything NOT matched by Chain 1.
     *
     * Security rules:
     *
     *   /login, /error → public (anyone can access — must be!)
     *
     *   /admin/**      → requires special "ADMIN_SECRET" header
     *                    This is our custom security for the Admin API.
     *                    Service B must send:
     *                      X-Admin-Secret: <secret from application.yml>
     *                    This replaces Docker network isolation since
     *                    you're not using Docker.
     *                    See AdminSecretFilter below for implementation.
     *
     *   everything else → must be logged in
     */
    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(
            HttpSecurity http) throws Exception {

        http
                .authorizeHttpRequests(authorize -> authorize
                        // Login page and error page: must be public
                        .requestMatchers("/login", "/error").permitAll()

                        /*
                         * /admin/** security:
                         *
                         * Since you're NOT using Docker, we can't rely on network
                         * isolation. Instead we use a "pre-shared secret" approach:
                         *
                         * Service B sends a special header with every admin request:
                         *   X-Admin-Secret: my-super-secret-admin-key-12345
                         *
                         * Auth Server checks this header.
                         * If missing or wrong → 403 Forbidden.
                         * If correct → allow.
                         *
                         * We mark it permitAll() here but our AdminSecretFilter
                         * (added below) does the actual secret check.
                         * This way it's NOT Spring's login that protects it —
                         * it's our own header-based check.
                         */
                        .requestMatchers("/admin/**").permitAll()

                        // All other URLs require the user to be logged in
                        .anyRequest().authenticated()
                )
                /*
                 * formLogin(withDefaults()) = enable Spring's built-in login page.
                 * Spring generates a proper HTML login form at /login automatically.
                 * You don't need to build it yourself!
                 *
                 * When user submits the form:
                 *   POST /login  { username: email, password: password }
                 * Spring Security:
                 *   1. Calls userService.loadUserByUsername(email)
                 *   2. Compares submitted password with stored BCrypt hash
                 *   3. If match → creates session, redirects to original URL
                 */
                .formLogin(Customizer.withDefaults())
                /*
                 * Tell Spring Security: use our UserService to look up users.
                 * Without this, Spring uses an in-memory user with random password.
                 * With this, Spring looks up users from our PostgreSQL database.
                 */
                .userDetailsService(userService)
                /*
                 * Add our custom filter that checks X-Admin-Secret header
                 * for /admin/** endpoints.
                 * See AdminSecretFilter class below.
                 */
                .addFilterBefore(
                        new AdminSecretFilter(),
                        org.springframework.security.web.authentication
                                .UsernamePasswordAuthenticationFilter.class
                );

        return http.build();
    }

    /**
     * passwordEncoder — BCrypt password hashing bean.
     *
     * @Bean = Spring creates ONE instance and shares it everywhere.
     * UserService gets it injected. DataInitializer gets it via UserService.
     *
     * BCryptPasswordEncoder:
     *   encode("Admin@123")   → "$2a$10$..."  (different every time)
     *   matches("Admin@123",
     *           "$2a$10$...") → true
     *
     * The "10" in "$2a$10$..." is the "cost factor" — higher = slower.
     * Default is 10. This means ~100ms to hash — slow enough for security.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}