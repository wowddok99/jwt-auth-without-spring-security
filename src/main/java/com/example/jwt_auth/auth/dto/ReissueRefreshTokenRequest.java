package com.example.jwt_auth.auth.dto;

public record ReissueRefreshTokenRequest (
    String token,
    String username
) {}
