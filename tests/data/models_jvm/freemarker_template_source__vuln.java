// expect: DF007
import freemarker.template.Configuration;
import freemarker.template.Template;
import javax.servlet.http.HttpServletRequest;
import java.io.StringReader;

public class Mailer {
    private Configuration cfg;

    public Template build(HttpServletRequest hreq) throws Exception {
        String body = hreq.getParameter("body");
        return new Template("mail", new StringReader(body), cfg);
    }
}
