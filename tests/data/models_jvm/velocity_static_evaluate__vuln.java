// expect: DF007
import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.Velocity;
import javax.servlet.http.HttpServletRequest;
import java.io.StringWriter;

public class Render {
    public String render(HttpServletRequest hreq) {
        StringWriter out = new StringWriter();
        Velocity.evaluate(new VelocityContext(), out, "page", hreq.getParameter("tpl"));
        return out.toString();
    }
}
