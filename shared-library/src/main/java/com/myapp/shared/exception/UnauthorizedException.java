package com.myapp.shared.exception;

public class UnauthorizedException extends RuntimeException {

    private static final int STATUS_CODE = 401;

    public UnauthorizedException(String message) {
        super(message);
    }

    public int getStatusCode() {
        return STATUS_CODE;
    }
}