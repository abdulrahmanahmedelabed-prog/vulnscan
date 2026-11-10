// expect: DF004
import javax.servlet.http.HttpServletRequest;
import java.sql.Connection;
import java.util.Enumeration;

public class Search {
    public void find(HttpServletRequest httpServletRequest, Connection conn) throws Exception {
        Enumeration<String> names = httpServletRequest.getParameterNames();
        String column = names.nextElement();
        conn.createStatement().executeQuery("SELECT " + column + " FROM items");
    }
}
