package ru.tveritin.security.model;

public enum Permission {
    Sellers_read("sellers:read"), //права доступа на чтение/запись
    Sellers_write("sellers:write");
    private final String permission;

    Permission(String permission) {
        this.permission = permission;
    }

    public String getPermission() {
        return permission;
    }
}
