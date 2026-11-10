// expect-none: DF013 DF012 DF010
import javax.servlet.http.HttpServletRequest;

public class Labels {
    public String label(HttpServletRequest hreq) {
        String name = hreq.getParameter("name");
        String text = String.format("Name: %s", name);
        java.util.Map<String, String> cache = new java.util.HashMap<>();
        cache.put("last", text);
        return cache.get(name).trim().isEmpty() ? "-" : "ok";
    }
}
