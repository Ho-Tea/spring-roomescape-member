package roomescape.configuration;

import java.util.Arrays;

import org.springframework.core.MethodParameter;
import org.springframework.http.HttpHeaders;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;

import roomescape.auth.domain.Member;
import roomescape.auth.service.AuthService;
import roomescape.exception.RoomEscapeException;

public class LoginMemberArgumentResolver implements HandlerMethodArgumentResolver {
    private final AuthService authService;

    public LoginMemberArgumentResolver(AuthService authService) {
        this.authService = authService;
    }

    @Override
    public boolean supportsParameter(MethodParameter parameter) {
        return parameter.hasParameterAnnotation(AuthenticatedMember.class)
                && parameter.getParameterType().equals(Member.class);
    }

    @Override
    public Object resolveArgument(MethodParameter parameter, ModelAndViewContainer mavContainer, NativeWebRequest webRequest, WebDataBinderFactory binderFactory) throws Exception {
        String[] cookies = webRequest.getHeaderValues(HttpHeaders.COOKIE);
        String token = getTokenBy(cookies);
        return authService.loginCheck(token);
    }

    private String getTokenBy(final String[] cookies) {
        if (cookies == null) {
            throw new RoomEscapeException("쿠키가 존재하지 않습니다.");
        }
        String token = Arrays.stream(cookies[0].split(";"))
                .map(String::trim)
                .filter(cookie -> cookie.startsWith("token"))
                .findFirst()
                .orElseThrow(() -> new RoomEscapeException("토큰이 존재하지 않습니다."));
        token = token.substring("token=".length());
        return token;
    }
}
