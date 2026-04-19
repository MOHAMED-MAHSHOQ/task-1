package com.myapp.shared.exception;

public class ValidationException extends RuntimeException {

    private static final int STATUS_CODE = 400;

    public ValidationException(String message) {
        super(message);
    }

    public int getStatusCode() {
        return STATUS_CODE;
    }
}