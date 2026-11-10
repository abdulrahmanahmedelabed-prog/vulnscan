// expect-none: DF012 DF007
import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.VelocityEngine;
import javax.servlet.http.HttpServletRequest;
import java.io.StringWriter;

public class Render2 {
    private VelocityEngine velocityEngine;

    public String render(HttpServletRequest hreq) {
        StringWriter out = new StringWriter();
        velocityEngine.evaluate(new VelocityContext(), out, "page", "Hello $name");
        return out.toString();
    }
}
