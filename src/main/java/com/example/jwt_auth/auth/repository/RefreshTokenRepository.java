package com.example.jwt_auth.auth.repository;

import com.example.jwt_auth.auth.entity.RefreshToken;
import com.example.jwt_auth.auth.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    Optional<RefreshToken> findByToken(String token);
    Optional<RefreshToken> findByUser(User user);
}
