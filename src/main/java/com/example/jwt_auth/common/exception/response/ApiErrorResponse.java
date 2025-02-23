package com.example.jwt_auth.common.exception.response;

import lombok.Builder;

@Builder
public record ApiErrorResponse(
        int status,
        String code,
        String message
) {}