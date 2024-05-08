package roomescape.reservation.service;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.when;

import java.time.LocalDate;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import roomescape.exception.RoomEscapeException;
import roomescape.exception.message.ExceptionMessage;
import roomescape.reservation.dao.ReservationDao;
import roomescape.reservation.dto.ReservationRequestDto;
import roomescape.theme.dao.ThemeDao;
import roomescape.theme.domain.Theme;
import roomescape.time.dao.ReservationTimeDao;
import roomescape.time.domain.ReservationTime;

@ExtendWith(MockitoExtension.class)
class ReservationServiceTest {

    @Mock
    private ReservationDao reservationDao;
    @Mock
    private ReservationTimeDao reservationTimeDao;
    @Mock
    private ThemeDao themeDao;

    @InjectMocks
    private ReservationService reservationService;

    @DisplayName("부적합한 날짜와 시간에 대한 예약 요청 시 예외가 발생한다.")
    @Test
    void save() {
        Long id = 1L;
        ReservationTime reservationTime = new ReservationTime(id, "00:00");
        Theme theme = new Theme(1L, "정글 모험", "열대 정글의 심연을 탐험하세요.", "https://i.pinimg.com/236x/6e/bc/46/6ebc461a94a49f9ea3b8bbe2204145d4.jpg");
        when(reservationTimeDao.getById(id)).thenReturn(reservationTime);
        when(themeDao.getById(id)).thenReturn(theme);
        when(reservationDao.checkExistByReservation(any(LocalDate.class), anyLong(), anyLong())).thenReturn(true);
        assertAll(
                () -> assertThatThrownBy(() -> reservationService.save(
                        new ReservationRequestDto("hotea", LocalDate.MAX.toString(), id, id)))
                        .isInstanceOf(RoomEscapeException.class)
                        .hasMessage(ExceptionMessage.DUPLICATE_DATE_TIME.getMessage()),
                () -> assertThatThrownBy(() -> reservationService.save(
                        new ReservationRequestDto("hotea", LocalDate.now().minusDays(1).toString(), id, id)))
                        .isInstanceOf(RoomEscapeException.class)
                        .hasMessage(ExceptionMessage.PAST_DATE_RESERVATION.getMessage()),
                () -> assertThatThrownBy(() -> reservationService.save(
                        new ReservationRequestDto("hotea", LocalDate.now().toString(), id, id)))
                        .isInstanceOf(RoomEscapeException.class)
                        .hasMessage(ExceptionMessage.PAST_TIME_RESERVATION.getMessage())
        );
    }
}
