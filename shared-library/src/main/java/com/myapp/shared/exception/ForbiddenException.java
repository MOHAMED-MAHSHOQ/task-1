package com.myapp.shared.exception;

public class ForbiddenException extends RuntimeException {

    private static final int STATUS_CODE = 403;

    public ForbiddenException(String message) {
        super(message);
    }

    public int getStatusCode() {
        return STATUS_CODE;
    }
}