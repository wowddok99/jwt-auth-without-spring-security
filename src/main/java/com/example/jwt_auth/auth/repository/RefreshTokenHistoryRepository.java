package com.example.jwt_auth.auth.repository;

import com.example.jwt_auth.auth.entity.RefreshTokenHistory;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RefreshTokenHistoryRepository extends JpaRepository<RefreshTokenHistory, Long> {
    Optional<RefreshTokenHistory> findByToken(String Token);
}
