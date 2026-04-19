package com.myapp.shared.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Getter;

@Getter
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ApiResponseDTO<T> {

    private final boolean success;
    private final T data;
    private final String error;
    private final int statusCode;

    private ApiResponseDTO(boolean success, T data, String error, int statusCode) {
        this.success = success;
        this.data = data;
        this.error = error;
        this.statusCode = statusCode;
    }

    public static <T> ApiResponseDTO<T> success(T data) {
        return new ApiResponseDTO<>(true, data, null, 200);
    }

    public static <T> ApiResponseDTO<T> success(T data, int statusCode) {
        return new ApiResponseDTO<>(true, data, null, statusCode);
    }

    public static <T> ApiResponseDTO<T> error(String message, int statusCode) {
        return new ApiResponseDTO<>(false, null, message, statusCode);
    }
}