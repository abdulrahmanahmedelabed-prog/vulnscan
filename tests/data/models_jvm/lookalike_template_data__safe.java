// expect-none: DF012 DF007
import freemarker.template.Configuration;
import freemarker.template.Template;
import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.Velocity;
import org.apache.velocity.app.VelocityEngine;
import javax.servlet.http.HttpServletRequest;
import java.io.StringReader;
import java.io.StringWriter;

public class Render3 {
    private VelocityEngine velocityEngine;
    private Configuration cfg;

    // user input only as template DATA (the Velocity context) or as the template's label, never as its source
    public String render(HttpServletRequest hreq) throws Exception {
        VelocityContext data = new VelocityContext();
        data.put("name", hreq.getParameter("name"));
        StringWriter out = new StringWriter();
        velocityEngine.evaluate(data, out, "page", "Hello $name");
        Velocity.evaluate(data, out, hreq.getParameter("tag"), "Bye $name");
        Template t = new Template(hreq.getParameter("tplName"), new StringReader("Hello ${name}"), cfg);
        return out.toString() + t.getName();
    }
}
