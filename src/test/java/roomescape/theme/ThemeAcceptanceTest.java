package roomescape.theme;

import static org.hamcrest.Matchers.is;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.annotation.DirtiesContext;

import io.restassured.RestAssured;
import io.restassured.http.ContentType;
import roomescape.theme.dto.ThemeRequestDto;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@DirtiesContext(classMode = DirtiesContext.ClassMode.BEFORE_EACH_TEST_METHOD)
public class ThemeAcceptanceTest {

    @LocalServerPort
    private int port;

    @BeforeEach
    void setUp() {
        RestAssured.port = port;
    }

    @Test
    void findAll() {
        RestAssured.given()
                   .when().get("/themes")
                   .then().statusCode(200)
                   .body("size()", is(0));
        save();
        RestAssured.given()
                   .when().get("/themes")
                   .then().statusCode(200)
                   .body("size()", is(1));
    }

    @Test
    void save() {
        ThemeRequestDto requestDto = new ThemeRequestDto("정글 모험", "열대 정글의 심연을 탐험하세요.", "https://i.pinimg.com/236x/6e/bc/46/6ebc461a94a49f9ea3b8bbe2204145d4.jpg");
        RestAssured.given()
                   .contentType(ContentType.JSON)
                   .body(requestDto)
                   .when().post("/themes")
                   .then().statusCode(201);
    }

    @Test
    void delete() {
        save();
        RestAssured.given()
                   .when().delete("/themes/1")
                   .then().statusCode(200);

        RestAssured.given()
                   .when().delete("/themes/1")
                   .then().statusCode(204);
    }
}
