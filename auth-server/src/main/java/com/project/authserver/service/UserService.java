// auth-server/src/main/java/com/project/authserver/service/UserService.java

package com.project.authserver.service;

import com.project.authserver.entity.User;
import com.project.authserver.repository.UserRepository;
import com.myapp.shared.dto.CreateUserDTO;
import com.myapp.shared.exception.NotFoundException;
import com.myapp.shared.exception.ValidationException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.UUID;

/*
 * @Service = Spring creates ONE instance of this class and manages it.
 * Any class that needs UserService just declares it as a constructor parameter
 * and Spring automatically provides it.
 *
 * UserDetailsService = Spring Security interface.
 * Spring Security calls loadUserByUsername() during the login process.
 * We implement this so Spring looks up users from OUR PostgreSQL database.
 */
@Service
@RequiredArgsConstructor
public class UserService implements UserDetailsService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    /*
     * Called automatically by Spring Security when user submits login form.
     *
     * Flow:
     *   User types email + password on login page
     *   → Spring calls loadUserByUsername(email)
     *   → We fetch user from DB
     *   → Return UserDetails (Spring's format for user info)
     *   → Spring compares submitted password with stored hash
     *   → If match: login success, session created
     *   → If mismatch: login failed, error shown
     *
     * NOTE: We return Spring Security's built-in User class here.
     * It has the same NAME as our entity (User) but is a DIFFERENT class.
     * Our entity: com.project.authserver.entity.User
     * Spring's:   org.springframework.security.core.userdetails.User
     * We use the full class name below to avoid confusion.
     */
    @Override
    public UserDetails loadUserByUsername(String username)
            throws UsernameNotFoundException {

        User user = userRepository.findByEmail(username)
                .orElseThrow(() -> new UsernameNotFoundException(
                        "User not found with email: " + username));

        return org.springframework.security.core.userdetails.User
                .withUsername(user.getEmail())
                .password(user.getPassword())   // already BCrypt hashed
                .roles(user.getRole())           // "USER" → stored as "ROLE_USER" internally
                .build();
    }

    /*
     * createUser — saves a new user to the Auth Server database.
     *
     * Called by:
     *   1. AdminUserController (SUPER_ADMIN creates user via /admin/users)
     *   2. Indirectly by DataInitializer (seeds default users on startup)
     *
     * Always hashes the password with BCrypt before saving.
     * NEVER saves plain text passwords.
     */
    public User createUser(CreateUserDTO dto) {
        // Reject if email already exists
        if (userRepository.existsByEmail(dto.getEmail())) {
            throw new ValidationException("Email already in use: " + dto.getEmail());
        }

        User user = new User();
        user.setName(dto.getName());
        user.setEmail(dto.getEmail());
        // BCrypt hash: "Admin@123" → "$2a$10$xyz..." (different every time, can't reverse)
        user.setPassword(passwordEncoder.encode(dto.getPassword()));
        user.setRole(dto.getRole());

        return userRepository.save(user);
    }

    public User updateUserRole(UUID userId, String newRole) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new NotFoundException(
                        "User not found with id: " + userId));
        user.setRole(newRole);
        return userRepository.save(user);
    }

    public List<User> getAllUsers() {
        return userRepository.findAll();
    }

    public User getUserById(UUID userId) {
        return userRepository.findById(userId)
                .orElseThrow(() -> new NotFoundException(
                        "User not found with id: " + userId));
    }

    public User findByEmail(String email) {
        return userRepository.findByEmail(email)
                .orElseThrow(() -> new NotFoundException(
                        "User not found with email: " + email));
    }

    /*
     * getPasswordEncoder — exposes the encoder bean to DataInitializer.
     *
     * WHY IS THIS NEEDED?
     * DataInitializer seeds users with FIXED UUIDs (so both databases use the same IDs).
     * To set a fixed UUID, we create the User entity manually and set the ID ourselves.
     * When creating the entity manually like this, we also need to hash the password manually.
     * That's why DataInitializer needs access to the PasswordEncoder.
     *
     * DataInitializer gets this via: userService.getPasswordEncoder().encode("Admin@123")
     */
    public PasswordEncoder getPasswordEncoder() {
        return passwordEncoder;
    }
}