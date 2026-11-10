// expect-none: DF004
import org.springframework.r2dbc.core.DatabaseClient;
import javax.servlet.http.HttpServletRequest;

public class Repo {
    private DatabaseClient databaseClient;

    public Object byCity(HttpServletRequest hreq) {
        String city = hreq.getParameter("city");
        return databaseClient.sql("SELECT * FROM shops WHERE city = :city").bind("city", city).fetch().all();
    }
}
