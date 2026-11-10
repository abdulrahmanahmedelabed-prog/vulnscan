// expect: DF007
import io.pebbletemplates.pebble.PebbleEngine;
import javax.servlet.http.HttpServletRequest;

public class Greeting {
    private PebbleEngine pebble = new PebbleEngine.Builder().build();

    public Object build(HttpServletRequest hreq) {
        return pebble.getLiteralTemplate(hreq.getParameter("greeting"));
    }
}
