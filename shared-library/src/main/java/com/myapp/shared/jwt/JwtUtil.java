package com.myapp.shared.jwt;

import com.myapp.shared.exception.UnauthorizedException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.security.SignatureException;

import java.security.PublicKey;
import java.util.UUID;

public class JwtUtil {
    private JwtUtil() {}

    public static DecodedClaims validateToken(String token, PublicKey publicKey) {
        try {

            Claims claims = Jwts.parser()
                    .verifyWith(publicKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
            String sub = claims.getSubject();

            String email = claims.get("email", String.class);

            String role = claims.get("role", String.class);

            String name = claims.get("name", String.class);

            UUID userId = UUID.fromString(sub);

            return new DecodedClaims(userId, email, role, name);

        } catch (ExpiredJwtException e) {
            throw new UnauthorizedException("Token has expired. Please log in again.");

        } catch (SignatureException e) {
            throw new UnauthorizedException("Token signature is invalid.");

        } catch (MalformedJwtException e) {
            throw new UnauthorizedException("Token is malformed.");

        } catch (Exception e) {
            throw new UnauthorizedException("Token validation failed: " + e.getMessage());
        }
    }

    public static String extractBearerToken(String authHeader) {
        if (authHeader == null || authHeader.isBlank()) {
            throw new UnauthorizedException("Authorization header is missing.");
        }

        if (!authHeader.startsWith("Bearer ")) {
            throw new UnauthorizedException(
                    "Authorization header must start with 'Bearer '");
        }

        String token = authHeader.substring(7);

        if (token.isBlank()) {
            throw new UnauthorizedException("Token is empty.");
        }

        return token;
    }
}