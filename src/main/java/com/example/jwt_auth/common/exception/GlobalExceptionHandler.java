package com.example.jwt_auth.common.exception;

import com.example.jwt_auth.common.exception.response.ApiErrorResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice // 내장된 AOP (다른 라이브러리 없이 사용 가능한 AOP)
public class GlobalExceptionHandler {
    // RuntimeException 및 하위 예외 처리 (예: IllegalArgumentException, NullPointerException 등)
    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<?> handleRuntimeException(RuntimeException exception) {
        var responseBody = ApiErrorResponse.builder()
                .status(HttpStatus.INTERNAL_SERVER_ERROR.value()) // 500 상태 코드
                .code(exception.getClass().getSimpleName())  // 발생한 예외의 클래스 이름 저장
                .message(exception.getMessage()) // 예외 메시지
                .build();

        return ResponseEntity
                .status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(responseBody);
    }
}