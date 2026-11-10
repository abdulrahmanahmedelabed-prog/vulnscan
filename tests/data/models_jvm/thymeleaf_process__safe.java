// expect-none: DF007
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;
import javax.servlet.http.HttpServletRequest;

public class Pages {
    private TemplateEngine templateEngine;

    public String page(HttpServletRequest hreq) {
        Context ctx = new Context();
        ctx.setVariable("q", hreq.getParameter("q"));
        return templateEngine.process("search", ctx);
    }
}
