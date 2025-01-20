package com.example.jwt_auth.auth.dto;

import lombok.Builder;

@Builder
public record SignUpResponse (
        String message,
        String userName,
        String nickName
) {
}
