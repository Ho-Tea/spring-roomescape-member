package roomescape.reservation.service;

import org.springframework.dao.DataAccessException;
import org.springframework.stereotype.Service;
import roomescape.exception.DuplicateReservationException;
import roomescape.exception.PastDateReservationException;
import roomescape.exception.PastTimeReservationException;
import roomescape.reservation.dao.ReservationDao;
import roomescape.reservation.domain.Reservation;
import roomescape.reservation.dto.ReservationRequestDto;
import roomescape.reservation.dto.ReservationResponseDto;
import roomescape.response.ResponseCode;
import roomescape.time.dao.ReservationTimeDao;
import roomescape.time.domain.ReservationTime;

import java.time.LocalDate;
import java.util.List;

@Service
public class ReservationService {

    private final ReservationDao reservationDao;
    private final ReservationTimeDao reservationTimeDao;

    public ReservationService(final ReservationDao reservationDao, final ReservationTimeDao reservationTimeDao) {
        this.reservationDao = reservationDao;
        this.reservationTimeDao = reservationTimeDao;
    }

    public List<ReservationResponseDto> findAll() {
        final List<Reservation> reservations = reservationDao.findAll();
        return reservations.stream()
                .map(ReservationResponseDto::new)
                .toList();
    }

    public ReservationResponseDto save(final ReservationRequestDto requestDto) {
        final ReservationTime reservationTime = reservationTimeDao.findById(requestDto.timeId());
        final Reservation reservation = requestDto.toReservation();
        validateNoReservationsForPastDates(reservation.getDate(), reservationTime);
        boolean isExist = reservationDao.checkReservationExists(reservation.getDate().toString(), reservationTime.getStartAt().toString());
        validateDuplicationReservation(isExist);

        final long reservationId = reservationDao.save(reservation);
        final Reservation findReservation = reservationDao.findById(reservationId);
        return new ReservationResponseDto(findReservation);
    }

    private void validateNoReservationsForPastDates(final LocalDate localDate, final ReservationTime time) {
        if (localDate.isBefore(LocalDate.now())) {
            throw new PastDateReservationException("날짜가 과거인 경우 모든 시간에 대한 예약이 불가능 합니다.");
        }
        if (localDate.equals(LocalDate.now()) && time.checkPastTime()) {
            throw new PastTimeReservationException("날짜가 오늘인 경우 지나간 시간에 대한 예약이 불가능 합니다.");
        }
    }

    private void validateDuplicationReservation(final boolean isExist) {
        if (isExist) {
            throw new DuplicateReservationException("이미 해당 날짜, 시간에 예약이 존재합니다.");
        }
    }

    public ResponseCode deleteById(final long id) {
        try {
            if (reservationDao.deleteById(id) > 0) {
                return ResponseCode.SUCCESS_DELETE;
            }
            return ResponseCode.NOT_FOUND;
        } catch (final DataAccessException dataAccessException) {
            return ResponseCode.FAILED_DELETE;
        }
    }
}
