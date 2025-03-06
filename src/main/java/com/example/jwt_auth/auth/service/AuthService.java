package com.example.jwt_auth.auth.service;

import com.example.jwt_auth.auth.dto.*;
import com.example.jwt_auth.auth.entity.RefreshToken;
import com.example.jwt_auth.auth.entity.RefreshTokenHistory;
import com.example.jwt_auth.auth.entity.User;
import com.example.jwt_auth.auth.repository.RefreshTokenHistoryRepository;
import com.example.jwt_auth.auth.repository.RefreshTokenRepository;
import com.example.jwt_auth.auth.repository.UserRepository;
import com.example.jwt_auth.common.jwt.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.NoSuchElementException;
import java.util.Optional;
import java.util.PrimitiveIterator;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final JwtUtil jwtUtil;
    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final RefreshTokenHistoryRepository refreshTokenHistoryRepository;
    private final TokenManagementService tokenManagementService;

    @Transactional(readOnly = true)
    public Optional<User> findByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    @Transactional
    public SignUpResponse signUp(SignUpRequest request) {
        // 새로운 사용자 객체 생성
        User newUser = User.builder()
                .username(request.username())
                .password(BCrypt.hashpw(request.password(), BCrypt.gensalt()))
                .email(request.email())
                .nickname(request.nickname())
                .role(request.role())
                .build();

        // 사용자 정보 저장(DB)
        User userPs = userRepository.save(newUser);

        return SignUpResponse.builder()
                .userName(userPs.getUsername())
                .nickName(userPs.getNickname())
                .message("회원가입이 완료되었습니다.")
                .build();
    }

    @Transactional
    public TokenResponse signIn(SignInRequest request) {
        // 사용자 이름으로 DB에서 사용자 조회
        User user = userRepository.findByUsername(request.username())
                .orElseThrow(() -> new NoSuchElementException("존재하지 않는 사용자입니다."));

        // 입력된 비밀번호와 저장된 비밀번호 비교
        if (!new BCryptPasswordEncoder().matches(request.password(), user.getPassword())) {
            throw new IllegalArgumentException("비밀번호가 일치하지 않습니다.");
        }

        // 기존 리프레시 토큰이 존재하는 경우, 사용 이력을 저장하고 토큰을 삭제
        refreshTokenRepository.findByUser(user).ifPresent(existingToken -> {
            RefreshTokenHistory history = RefreshTokenHistory.builder()
                    .user(user)
                    .token(existingToken.getToken())
                    .usedAt(Instant.now())
                    .expiryDate(existingToken.getExpiryDate())
                    .build();

            refreshTokenHistoryRepository.save(history);
            refreshTokenRepository.delete(existingToken);
        });

        // 새로운 액세스 토큰 및 리프레시 토큰 생성
        String accessToken = jwtUtil.createAccessToken(user);
        String refreshToken = jwtUtil.createRefreshToken(user);

        // 해싱된 리프레시 토큰 생성(DB 저장용)
        RefreshToken hashedRefreshToken = RefreshToken.builder()
                .user(user)
                .token(BCrypt.hashpw(refreshToken, BCrypt.gensalt()))
                .expiryDate(Instant.now().plusSeconds(7 * 24 * 60 * 60)) // 7일 후 만료
                .build();

        // 해싱된 리프레시 토큰 저장(DB)
        refreshTokenRepository.save(hashedRefreshToken);

        return TokenResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }

    @Transactional
    public TokenResponse reissueRefreshToken(ReissueRefreshTokenRequest request) {
        // 사용자 이름으로 DB에서 사용자 조회
        User existingUser = userRepository.findByUsername(request.username())
                .orElseThrow(() -> new NoSuchElementException("존재하지 않는 사용자입니다."));

        // 주어진 토큰이 만료된 리프레시 토큰 기록에 존재하는지 확인
        refreshTokenHistoryRepository.findByToken(request.token())
                .ifPresent(refreshTokenHistory -> {
                    // 리프레시 토큰 재사용 처리 (재사용 횟수 증가 및 해당 유저의 모든 리프레시 토큰 삭제)
                    tokenManagementService.handleRefreshTokenReuse(refreshTokenHistory);

                    throw new IllegalArgumentException("사용 또는 만료 처리된 리프레시 토큰이 재사용 되었습니다.");
                });

        // 해당 사용자의 모든 리프레시 토큰을 가져온 후, 해시된 값 비교
        RefreshToken existingRefreshToken = refreshTokenRepository.findByUser(existingUser)
                .stream()
                .filter(refreshToken -> BCrypt.checkpw(request.token(), refreshToken.getToken()))
                .findFirst()
                .orElseThrow(() -> new NoSuchElementException("리프레시 토큰이 존재하지 않습니다."));

        // 리프레시 토큰 만료 여부 체크
        if (existingRefreshToken.isExpired()) {
            throw new IllegalArgumentException("리프레시 토큰이 만료되었습니다.");
        }

        // 기존 리프레시 토큰 사용 기록 객체 생성
        RefreshTokenHistory refreshTokenHistory = RefreshTokenHistory.builder()
                .user(existingUser)
                .token(request.token())
                .usedAt(Instant.now())
                .expiryDate(existingRefreshToken.getExpiryDate())
                .build();

        // 기존 리프레시 토큰 사용 기록 저장
        refreshTokenHistoryRepository.save(refreshTokenHistory);

        // 기존 리프레시 토큰 삭제(재사용 방지)
        refreshTokenRepository.delete(existingRefreshToken);

        // 새로운 액세스 토큰 및 리프레시 토큰 생성
        String newAccessToken = jwtUtil.createAccessToken(existingUser);
        String newRefreshToken = jwtUtil.createRefreshToken(existingUser);

        // 해싱된 리프레시 토큰 생성(DB 저장용)
        RefreshToken hashedRefreshToken = RefreshToken.builder()
                .user(existingUser)
                .token(BCrypt.hashpw(newRefreshToken, BCrypt.gensalt()))
                .expiryDate(Instant.now().plusSeconds(7 * 24 * 60 * 60)) // 7일
                .build();

        // 해싱된 리프레시 토큰 저장(DB)
        refreshTokenRepository.save(hashedRefreshToken);

        return TokenResponse.builder()
                .accessToken(newAccessToken)
                .refreshToken(newRefreshToken)
                .build();
    }
}
