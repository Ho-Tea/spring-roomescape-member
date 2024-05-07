package roomescape.reservation.dao.mapper;

import java.sql.ResultSet;
import java.sql.SQLException;

import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Component;

import roomescape.reservation.domain.Reservation;
import roomescape.theme.domain.Theme;
import roomescape.time.domain.ReservationTime;

@Component
public class ReservationRowMapper implements RowMapper<Reservation> {

    @Override
    public Reservation mapRow(final ResultSet resultSet, final int rowNum) throws SQLException {
        return Reservation.createWithId(
                resultSet.getLong("reservation_id"),
                resultSet.getString("reservation_name"),
                resultSet.getString("date"),
                ReservationTime.createWithId(
                        resultSet.getLong("time_id"),
                        resultSet.getString("time_value")
                ),
                Theme.createWithId(
                        resultSet.getLong("theme_id"),
                        resultSet.getString("theme_name"),
                        resultSet.getString("description"),
                        resultSet.getString("thumbnail")
                )
        );
    }
}
