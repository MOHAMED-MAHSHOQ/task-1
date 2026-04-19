// auth-server/src/main/java/com/project/authserver/controller/AdminUserController.java

package com.project.authserver.controller;

import com.project.authserver.entity.User;
import com.project.authserver.service.UserService;
import com.myapp.shared.dto.ApiResponseDTO;
import com.myapp.shared.dto.CreateUserDTO;
import com.myapp.shared.dto.RoleUpdateDTO;
import com.myapp.shared.dto.UserProfileDTO;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

/*
 * @RestController = @Controller + @ResponseBody combined.
 *
 *   @Controller    = marks this class as a web controller.
 *                    Spring will route HTTP requests to methods in this class.
 *
 *   @ResponseBody  = every method's return value is automatically
 *                    converted to JSON and written to the HTTP response.
 *                    Without this, Spring would try to find an HTML template.
 *
 * @RequestMapping("/admin") = ALL URLs in this class start with /admin.
 *   @GetMapping("/users") inside this class = GET /admin/users
 *   @PostMapping("/users") inside this class = POST /admin/users
 *
 * SECURITY: These endpoints are protected by AdminSecretFilter.
 * Every request to /admin/** must include header: X-Admin-Secret: <secret>
 * Only Service B knows this secret and sends it.
 * Direct calls from browser/Postman without the header → 401 rejected.
 */
@RestController
@RequestMapping("/admin")
@RequiredArgsConstructor
public class AdminUserController {

    private final UserService userService;

    /*
     * POST /admin/users — Create a new user.
     *
     * Called by Service B when SUPER_ADMIN creates a user via React /admin page.
     *
     * @RequestBody CreateUserDTO dto
     *   = read the JSON request body and convert it to a CreateUserDTO object.
     *   Spring uses Jackson (JSON library) to do this automatically.
     *   Example request body: { "name": "Alice", "email": "alice@co.com",
     *                           "password": "pass123", "role": "MANAGER" }
     *
     * @Valid
     *   = run the validation annotations on CreateUserDTO BEFORE the method body runs.
     *   If email is not valid format → Spring auto-returns HTTP 400 with error message.
     *   If name is blank → Spring auto-returns HTTP 400.
     *   Our method body only runs if ALL validations pass.
     *
     * ResponseEntity<T> = represents the full HTTP response:
     *   body    = the JSON data
     *   status  = HTTP status code (200, 201, 400, etc.)
     *
     * ResponseEntity.status(HttpStatus.CREATED).body(...)
     *   = HTTP 201 Created + JSON body
     *   201 means "resource was successfully created" (vs 200 which means "OK")
     */
    @PostMapping("/users")
    public ResponseEntity<ApiResponseDTO<UserProfileDTO>> createUser(
            @Valid @RequestBody CreateUserDTO dto) {

        User user = userService.createUser(dto);

        /*
         * IMPORTANT: Never return the User entity directly!
         * The User entity has a "password" field.
         * If we returned it, the hashed password would be in the JSON response.
         * Always convert to UserProfileDTO which has NO password field.
         */
        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(ApiResponseDTO.success(toDTO(user), 201));
    }

    /*
     * PATCH /admin/users/{id}/role — Update a user's role.
     *
     * Called by Service B when SUPER_ADMIN promotes USER → MANAGER.
     *
     * @PathVariable UUID id
     *   = extract {id} from the URL path.
     *   Example: PATCH /admin/users/22222222-2222-2222-2222-222222222222/role
     *   → id = UUID object with value 22222222-2222-...
     *
     * Spring automatically converts the UUID string from the URL
     * to a java.util.UUID object. If the string isn't a valid UUID → 400 error.
     *
     * PATCH (not PUT) because we're updating ONE field (role), not the whole user.
     * PUT would replace the entire user. PATCH is for partial updates.
     */
    @PatchMapping("/users/{id}/role")
    public ResponseEntity<ApiResponseDTO<UserProfileDTO>> updateRole(
            @PathVariable UUID id,
            @Valid @RequestBody RoleUpdateDTO dto) {

        User updated = userService.updateUserRole(id, dto.getRole());
        return ResponseEntity.ok(ApiResponseDTO.success(toDTO(updated)));
    }

    /*
     * GET /admin/users — Get all users.
     *
     * Called by Service B when SUPER_ADMIN opens the user list in React.
     *
     * .stream() = convert the List to a Stream for processing.
     * .map(this::toDTO) = for each User entity, call our toDTO() method.
     *   this::toDTO is a "method reference" — shorthand for: user -> toDTO(user)
     * .toList() = collect results back into a List.
     *
     * This converts List<User entity> → List<UserProfileDTO> (no passwords).
     */
    @GetMapping("/users")
    public ResponseEntity<ApiResponseDTO<List<UserProfileDTO>>> getAllUsers() {
        List<UserProfileDTO> users = userService.getAllUsers()
                .stream()
                .map(this::toDTO)
                .toList();
        return ResponseEntity.ok(ApiResponseDTO.success(users));
    }

    /*
     * GET /admin/users/{id} — Get a single user by UUID.
     *
     * Called by Service B when it needs details of one specific user.
     */
    @GetMapping("/users/{id}")
    public ResponseEntity<ApiResponseDTO<UserProfileDTO>> getUserById(
            @PathVariable UUID id) {
        User user = userService.getUserById(id);
        return ResponseEntity.ok(ApiResponseDTO.success(toDTO(user)));
    }

    /*
     * toDTO — converts User entity to UserProfileDTO.
     *
     * "private" = only used within this controller class.
     *
     * This is a "mapper" method. Its job is to copy data from
     * the entity (which has all fields including password)
     * to the DTO (which only has safe fields to return to caller).
     *
     * Always do this before returning user data from any endpoint.
     */
    private UserProfileDTO toDTO(User user) {
        return new UserProfileDTO(
                user.getId(),
                user.getName(),
                user.getEmail(),
                user.getRole(),
                user.getProfilePic()
        );
    }
}