// expect-none: DF013 DF010 DF014
import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;

public class Misc {
    // System.out/err are the server console, not the HTTP response; `rest` is an ordinary map;
    // a project class named Filter is not the UnboundID LDAP Filter
    public void handle(HttpServletRequest hreq) {
        String v = hreq.getParameter("v");
        System.out.printf("got %s%n", v);
        System.err.format("got %s%n", v);
        Map<String, String> rest = new HashMap<>();
        rest.put(v, "1");
        rest.delete(v);
        com.example.search.Filter.create(v);
    }
}
