package com.myapp.shared.exception;

public class NotFoundException extends RuntimeException {

    private static final int STATUS_CODE = 404;

    public NotFoundException(String message) {
        super(message);
    }

    public int getStatusCode() {
        return STATUS_CODE;
    }
}