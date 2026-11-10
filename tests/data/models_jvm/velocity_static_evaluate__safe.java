// expect-none: DF007
import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.Velocity;
import javax.servlet.http.HttpServletRequest;
import java.io.StringWriter;

public class Render {
    public String render(HttpServletRequest hreq) {
        StringWriter out = new StringWriter();
        VelocityContext vc = new VelocityContext();
        Velocity.evaluate(vc, out, "page", "Hello $name");
        return out.toString();
    }
}
