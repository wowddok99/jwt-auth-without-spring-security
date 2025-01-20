package com.example.jwt_auth.auth.dto;

import com.example.jwt_auth.auth.entity.role.Role;
import lombok.Builder;

@Builder
public record SignUpRequest(
        String username,
        String password,
        String email,
        String nickname,
        Role role
) {}
