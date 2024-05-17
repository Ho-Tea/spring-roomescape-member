package roomescape.member.dto;

import java.util.Objects;

import jakarta.annotation.Nullable;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

import roomescape.member.domain.Member;
import roomescape.member.domain.Role;

public record MemberRequestDto(
        @Email(message = "이메일 형식으로 입력해야 합니다.(ex: email@email.com)") String email,
        @NotBlank(message = "비밀번호를 입력해야 합니다.") String password,
        @NotBlank(message = "사용자 이름을 입력해야 합니다.") String name,
        @Nullable Role role
) {
    public MemberRequestDto(
            @Email(message = "이메일 형식으로 입력해야 합니다.(ex: email@email.com)") String email,
            @NotBlank(message = "비밀번호를 입력해야 합니다.") String password,
            @NotBlank(message = "사용자 이름을 입력해야 합니다.") String name,
            @Nullable Role role) {
        this.email = email;
        this.password = password;
        this.name = name;
        this.role = injectRole(role);
    }

    public Member toMemberOf(final String password) {
        return new Member(email, password, name, role);
    }

    private Role injectRole(final Role role) {
        if (Objects.isNull(role)) {
            return Role.USER;
        }
        return role;
    }
}
