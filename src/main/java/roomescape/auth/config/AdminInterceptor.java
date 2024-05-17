package roomescape.auth.config;


import java.util.Arrays;
import java.util.Objects;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.http.HttpHeaders;
import org.springframework.web.servlet.HandlerInterceptor;

import roomescape.auth.service.AuthService;
import roomescape.exception.ForbiddenException;
import roomescape.exception.UnAuthorizationException;
import roomescape.member.domain.Role;

public class AdminInterceptor implements HandlerInterceptor {
    private static final String AUTHORIZATION = "token";
    private static final String DELIMITER = ";";
    private final AuthService adminService;

    public AdminInterceptor(final AuthService adminService) {
        this.adminService = adminService;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        String cookie = request.getHeader(HttpHeaders.COOKIE);
        validateValueIsNotNull(cookie);
        String token = getTokenByCookie(cookie);
        validateValueIsNotNull(token);
        return checkAdmin(token);
    }

    private boolean checkAdmin(final String token) {
        Role role = adminService.extractMemberBy(token.substring(AUTHORIZATION.length() + 1)).getRole();
        if (role == Role.ADMIN) {
            return true;
        }
        throw new ForbiddenException("접근 권한이 없는 사용자입니다.");
    }

    private void validateValueIsNotNull(final String value) {
        if (Objects.isNull(value)) {
            throw new UnAuthorizationException("접근 권한이 없는 사용자입니다.");
        }
    }

    private String getTokenByCookie(final String cookie) {
        return Arrays.stream(cookie.split(DELIMITER))
                .map(String::trim)
                .filter(it -> it.startsWith(AUTHORIZATION))
                .findFirst()
                .orElse(null);
    }
}
