package com.example.jwt_auth.auth.dto;

import lombok.Builder;

@Builder
public record SignInRequest(
        String username,
        String password
) {}
