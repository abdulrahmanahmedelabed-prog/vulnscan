// expect-none: DF004
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.reactive.function.server.ServerRequest;

public class Orders {
    private JdbcTemplate jdbcTemplate;

    public Object byId(ServerRequest serverRequest) {
        long id = Long.parseLong(serverRequest.pathVariable("id"));
        return jdbcTemplate.queryForRowSet("SELECT * FROM orders WHERE id = " + id);
    }
}
