package roomescape.auth.config;

import java.util.Arrays;

import org.springframework.core.MethodParameter;
import org.springframework.http.HttpHeaders;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;

import roomescape.auth.annotation.AuthenticatedMember;
import roomescape.auth.service.AuthService;
import roomescape.exception.UnAuthorizationException;
import roomescape.member.domain.Member;

public class LoginArgumentResolver implements HandlerMethodArgumentResolver {
    private static final String AUTHORIZATION = "token";
    private static final String DELIMITER = ";";
    private final AuthService authService;

    public LoginArgumentResolver(AuthService authService) {
        this.authService = authService;
    }

    @Override
    public boolean supportsParameter(MethodParameter parameter) {
        return parameter.hasParameterAnnotation(AuthenticatedMember.class)
                && parameter.getParameterType().equals(Member.class);
    }

    @Override
    public Object resolveArgument(
            MethodParameter parameter,
            ModelAndViewContainer mavContainer,
            NativeWebRequest webRequest,
            WebDataBinderFactory binderFactory) {
        String[] cookies = webRequest.getHeaderValues(HttpHeaders.COOKIE);
        String token = getTokenByCookies(cookies);
        return authService.extractMemberBy(token);
    }

    private String getTokenByCookies(final String[] cookies) {
        if (cookies == null) {
            throw new UnAuthorizationException("쿠키가 존재하지 않습니다.");
        }
        String token = Arrays.stream(cookies[0].split(DELIMITER))
                .map(String::trim)
                .filter(cookie -> cookie.startsWith(AUTHORIZATION))
                .findFirst()
                .orElseThrow(() -> new UnAuthorizationException("토큰이 존재하지 않습니다."));
        return token.substring(AUTHORIZATION.length() + 1);
    }
}
