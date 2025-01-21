package com.example.jwt_auth.post;

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/post")
public class PostApi {
    @GetMapping
    public String getPost() {
        return "게시글 조회 완료";
    }
}