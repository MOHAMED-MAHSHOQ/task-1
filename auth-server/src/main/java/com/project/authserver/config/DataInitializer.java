// auth-server/src/main/java/com/project/authserver/config/DataInitializer.java

package com.project.authserver.config;

import com.project.authserver.entity.User;
import com.project.authserver.repository.UserRepository;
import com.project.authserver.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

import java.util.UUID;

/*
 * @Component = Spring creates and manages this class as a bean.
 *
 * CommandLineRunner = a Spring Boot interface.
 * Any class that implements it gets its run() method called
 * AUTOMATICALLY after the Spring application has fully started.
 *
 * "After fully started" means:
 *   ✓ Database connection is ready
 *   ✓ All beans are created
 *   ✓ All tables exist (Hibernate already ran ddl-auto: update)
 * So it's safe to insert data here.
 *
 * @Slf4j (Lombok) = creates a logger field automatically:
 *   private static final Logger log = LoggerFactory.getLogger(DataInitializer.class);
 * Used as: log.info("message") → prints to console during startup.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class DataInitializer implements CommandLineRunner {

    private final UserRepository userRepository;
    private final UserService userService;

    /*
     * FIXED UUIDs — Why hardcoded?
     *
     * Both Auth Server DB and Service B DB need to store the SAME users.
     * Both databases link users by UUID (same UUID = same person).
     *
     * If we let JPA auto-generate UUIDs:
     *   Auth Server startup → generates UUID "aaa-111" for superadmin
     *   Service B startup   → generates UUID "bbb-222" for superadmin
     *   → They're now different UUIDs = broken link between databases!
     *
     * Solution: hardcode UUIDs here AND in Service B's DataInitializer.
     * Same UUID in both = same person.
     *
     * "public static final" = constant, accessible from other classes:
     *   DataInitializer.SUPER_ADMIN_UUID
     */
    public static final UUID SUPER_ADMIN_UUID =
            UUID.fromString("11111111-1111-1111-1111-111111111111");
    public static final UUID MANAGER_UUID =
            UUID.fromString("22222222-2222-2222-2222-222222222222");
    public static final UUID USER_UUID =
            UUID.fromString("33333333-3333-3333-3333-333333333333");

    /*
     * run() — called automatically by Spring Boot after startup.
     *
     * args = command-line arguments passed when starting the app.
     * We don't use them, but CommandLineRunner requires this signature.
     */
    @Override
    public void run(String... args) {
        log.info("========== Starting Data Initialization ==========");

        seedUser(SUPER_ADMIN_UUID, "Super Admin",
                "superadmin@app.com", "Admin@123", "SUPER_ADMIN");

        seedUser(MANAGER_UUID, "Manager",
                "manager@app.com", "Manager@123", "MANAGER");

        seedUser(USER_UUID, "User",
                "user@app.com", "User@123", "USER");

        log.info("========== Data Initialization Complete ==========");
    }

    /*
     * seedUser — inserts ONE user if they don't already exist.
     *
     * This is "idempotent" — safe to run multiple times.
     *
     *   1st server startup: user doesn't exist → CREATE
     *   2nd server startup: user already exists → SKIP (no error)
     *   3rd server startup: user already exists → SKIP (no error)
     *
     * WHY NOT just use userService.createUser()?
     * Because createUser() lets JPA auto-generate the UUID.
     * Here we NEED to set the UUID manually to a fixed value.
     *
     * JPA behaviour:
     *   If id == null → JPA generates a new UUID
     *   If id != null → JPA uses the ID we set ← This is what we want
     */
    private void seedUser(UUID id, String name, String email,
                          String rawPassword, String role) {

        // Check first — "does a user with this email already exist?"
        if (userRepository.existsByEmail(email)) {
            log.info("  ↳ Skipping (already exists): {}", email);
            return; // Skip, don't try to insert again
        }

        // Build the User entity manually so we can set the fixed UUID
        User user = new User();
        user.setId(id);          // Set fixed UUID — both DBs use this same ID
        user.setName(name);
        user.setEmail(email);

        /*
         * Hash the password before saving.
         * NEVER store plain text passwords.
         *
         * userService.getPasswordEncoder() gives us the BCryptPasswordEncoder.
         * .encode("Admin@123") → "$2a$10$N9qo8uLO..." (BCrypt hash)
         *
         * BCrypt properties:
         *   - One-way: can NEVER go back from hash to "Admin@123"
         *   - Random salt: same password → different hash every time
         *   - Slow by design: brute force takes years
         */
        user.setPassword(
                userService.getPasswordEncoder().encode(rawPassword)
        );
        user.setRole(role);

        /*
         * Default profile picture using ui-avatars.com — a free service.
         * It generates an avatar image from initials.
         *
         * "Super Admin" → shows "SA" in a colored circle
         * "Manager"     → shows "M" in a colored circle
         * "User"        → shows "U" in a colored circle
         *
         * URL pattern: https://ui-avatars.com/api/?name=First+Last&...
         * .replace(" ", "+") converts "Super Admin" to "Super+Admin" for URL
         */
        user.setProfilePic(
                "https://ui-avatars.com/api/?name="
                        + name.replace(" ", "+")
                        + "&background=random&size=200"
        );

        userRepository.save(user);
        log.info("  ↳ Created: {} | role: {}", email, role);
    }
}