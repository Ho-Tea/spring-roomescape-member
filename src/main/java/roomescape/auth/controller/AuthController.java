package roomescape.auth.controller;

import java.util.Date;

import jakarta.validation.Valid;

import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import roomescape.auth.annotation.AuthenticatedMember;
import roomescape.auth.dto.LoginRequestDto;
import roomescape.auth.dto.LoginResponseDto;
import roomescape.auth.service.AuthService;
import roomescape.member.domain.Member;

@RestController
public class AuthController {
    private static final long VALID_TIME = 3600;
    private static final long INVALID_TIME = 0;
    private static final String AUTHORIZATION = "token";
    private static final String REDIRECT_URI = "/";

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/login")
    public ResponseEntity<Void> login(@RequestBody @Valid LoginRequestDto loginRequestDto) {
        String token = authService.login(loginRequestDto);
        ResponseCookie cookie = ResponseCookie.from(AUTHORIZATION, token)
                .httpOnly(true)
                .path(REDIRECT_URI)
                .maxAge(VALID_TIME)
                .build();
        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.SET_COOKIE, cookie.toString());
        return ResponseEntity.ok().headers(headers).build();
    }

    @GetMapping("/login/check")
    public ResponseEntity<LoginResponseDto> loginCheck(@AuthenticatedMember Member member) {
        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.DATE, new Date().toString());
        return ResponseEntity.ok().headers(headers).body(new LoginResponseDto(member.getName()));
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout() {
        ResponseCookie cookie = ResponseCookie.from(AUTHORIZATION, null)
                .maxAge(INVALID_TIME)
                .build();
        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.SET_COOKIE, cookie.toString());
        return ResponseEntity.ok().headers(headers).build();
    }
}
