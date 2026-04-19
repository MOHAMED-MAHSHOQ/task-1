package com.myapp.shared.role;

public class RoleUtil {
    private RoleUtil() {}

    public static boolean hasPermission(Role userRole, Role requiredRole) {
        return userRole.getLevel() <= requiredRole.getLevel();
    }

    public static Role fromString(String roleStr) {
        try {
            return Role.valueOf(roleStr.toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid role: " + roleStr +
                    ". Valid roles are: SUPER_ADMIN, MANAGER, USER");
        }
    }
}