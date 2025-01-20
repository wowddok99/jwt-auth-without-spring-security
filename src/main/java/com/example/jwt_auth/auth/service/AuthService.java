package com.example.jwt_auth.auth.service;

import com.example.jwt_auth.auth.dto.SignInRequest;
import com.example.jwt_auth.auth.dto.SignUpRequest;
import com.example.jwt_auth.auth.dto.SignUpResponse;
import com.example.jwt_auth.auth.dto.TokenResponse;
import com.example.jwt_auth.auth.entity.RefreshToken;
import com.example.jwt_auth.auth.entity.User;
import com.example.jwt_auth.auth.repository.RefreshTokenRepository;
import com.example.jwt_auth.auth.repository.UserRepository;
import com.example.jwt_auth.common.jpa.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final JwtUtil jwtUtil;
    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;

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

        // 사용자 정보 저장
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
                .orElseThrow(() -> new IllegalArgumentException("존재하지 않는 사용자입니다."));

        // 입력된 비밀번호와 저장된 비밀번호 비교
        if (!new BCryptPasswordEncoder().matches(request.password(), user.getPassword())) {
            throw new IllegalArgumentException("비밀번호가 일치하지 않습니다.");
        }

        // 새로운 액세스 토큰 생성
        String accessToken = jwtUtil.createAccessToken(user);

        // 새로운 리프레시 토큰 생성
        String refreshToken = jwtUtil.createRefreshToken(user);

        RefreshToken refreshTokenEntity = RefreshToken.builder()
                .user(user)
                .token(refreshToken)
                .build();

        // 리프레시 토큰 저장
        refreshTokenRepository.save(refreshTokenEntity);

        return TokenResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }

    public Optional<User> findByUsername(String username) {
        return userRepository.findByUsername(username);
    }
}
