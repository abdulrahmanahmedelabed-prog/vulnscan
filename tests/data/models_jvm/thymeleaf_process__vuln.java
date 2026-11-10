// expect: DF007
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;
import javax.servlet.http.HttpServletRequest;

public class Pages {
    private TemplateEngine templateEngine;

    public String page(HttpServletRequest hreq) {
        return templateEngine.process(hreq.getParameter("template"), new Context());
    }
}
