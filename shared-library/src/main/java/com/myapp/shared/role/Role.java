package com.myapp.shared.role;

public enum Role {

    SUPER_ADMIN(0),

    MANAGER(1),

    USER(2);

    private final int level;

    Role(int level) {
        this.level = level;
    }

    public int getLevel() {
        return level;
    }
}