// expect-none: DF012
import groovy.lang.GroovyShell;
import javax.servlet.http.HttpServletRequest;

public class Scripts {
    public Object run(HttpServletRequest hreq) {
        GroovyShell shell = new GroovyShell();
        shell.setVariable("x", hreq.getParameter("x"));
        return shell.parse("x.toUpperCase()").run();
    }
}
