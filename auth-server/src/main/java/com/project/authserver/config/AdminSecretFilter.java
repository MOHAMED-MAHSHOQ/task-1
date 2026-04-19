// auth-server/src/main/java/com/project/authserver/config/AdminSecretFilter.java

package com.project.authserver.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/*
 * AdminSecretFilter — protects /admin/** endpoints.
 *
 * WHAT IS A FILTER?
 * Every HTTP request passes through a "chain" of filters before reaching a controller.
 *
 *   Browser sends request
 *       ↓
 *   Filter 1 (logging)
 *       ↓
 *   Filter 2 (authentication check)
 *       ↓
 *   Filter 3 ← AdminSecretFilter (our custom filter)
 *       ↓
 *   Controller (if all filters allow it)
 *
 * A filter can either:
 *   a) Pass the request through: call chain.doFilter(request, response)
 *   b) Block the request: write a response directly and return (don't call doFilter)
 *
 * OncePerRequestFilter = Spring base class that guarantees:
 *   - This filter runs exactly ONCE per request (no duplicates)
 *   - Provides the convenient doFilterInternal() method to override
 *
 * HOW ADMIN SECURITY WORKS (without Docker network isolation):
 *
 *   Service B → sends header → Auth Server
 *   Header: X-Admin-Secret: dev-admin-secret-change-in-production-xyz-12345
 *
 *   AdminSecretFilter checks:
 *     ✓ Is this a /admin/** request? If not → skip this filter entirely
 *     ✓ Is X-Admin-Secret header present? If not → return 401
 *     ✓ Does the value match our secret? If not → return 403
 *     ✓ All good → allow request through to controller
 *
 * Both Auth Server and Service B have the SAME secret in their application.yml.
 * This is called a "pre-shared secret" or "API key" pattern.
 */
@Component
public class AdminSecretFilter extends OncePerRequestFilter {

    /*
     * @Value("${admin.secret}") = reads the value from application.yml.
     *
     * In application.yml:
     *   admin:
     *     secret: "dev-admin-secret-change-in-production-xyz-12345"
     *
     * Spring reads that YAML value and injects it into this field.
     * The ${...} syntax = "read this property from configuration".
     *
     * This way the secret is NOT hardcoded in Java source code.
     * To change the secret, you only change application.yml (or an env variable).
     */
    @Value("${admin.secret}")
    private String adminSecret;

    /*
     * doFilterInternal — runs for every HTTP request that reaches this filter.
     *
     * @param request     The incoming HTTP request (we READ from this)
     * @param response    The outgoing HTTP response (we WRITE to this if blocking)
     * @param filterChain The rest of the filter chain (call this to continue)
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        String requestPath = request.getRequestURI();

        /*
         * Step 1: Is this even an /admin/** request?
         * If not, skip this filter entirely and let it through.
         * This filter should ONLY affect /admin/** URLs.
         *
         * filterChain.doFilter() = "pass to next filter, I'm done"
         * return = stop executing this method (filter is done)
         */
        if (!requestPath.startsWith("/admin/")) {
            filterChain.doFilter(request, response);
            return;
        }

        /*
         * Step 2: Check the X-Admin-Secret header.
         * request.getHeader("X-Admin-Secret") = get this specific header value.
         * Returns null if the header is not present in the request.
         */
        String providedSecret = request.getHeader("X-Admin-Secret");

        if (providedSecret == null || providedSecret.isBlank()) {
            /*
             * Header is missing → Unauthorized (401).
             *
             * response.setStatus(401) = set HTTP status code to 401.
             * response.setContentType("application/json") = tell caller it's JSON.
             * response.getWriter().write(...) = write the response body.
             *
             * After writing the response, we RETURN without calling filterChain.doFilter().
             * NOT calling doFilter() = STOP HERE. Controller never receives this request.
             */
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED); // 401
            response.setContentType("application/json");
            response.getWriter().write(
                    "{\"success\":false," +
                            "\"error\":\"X-Admin-Secret header is missing\"," +
                            "\"statusCode\":401}"
            );
            return; // ← STOP. Don't continue to controller.
        }

        if (!adminSecret.equals(providedSecret)) {
            /*
             * Header is present but value is WRONG → Forbidden (403).
             *
             * 401 = "I don't know who you are" (missing credentials)
             * 403 = "I know who you are but you're not allowed" (wrong credentials)
             */
            response.setStatus(HttpServletResponse.SC_FORBIDDEN); // 403
            response.setContentType("application/json");
            response.getWriter().write(
                    "{\"success\":false," +
                            "\"error\":\"Invalid admin secret\"," +
                            "\"statusCode\":403}"
            );
            return; // ← STOP. Don't continue to controller.
        }

        /*
         * Step 3: Secret is correct → allow through.
         * filterChain.doFilter() = "pass request to next filter/controller"
         * Execution continues to AdminUserController.
         */
        filterChain.doFilter(request, response);
    }
}