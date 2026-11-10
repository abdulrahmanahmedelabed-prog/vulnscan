// expect: DF012
import groovy.lang.GroovyShell;
import javax.servlet.http.HttpServletRequest;

public class Scripts {
    public Object run(HttpServletRequest hreq) {
        GroovyShell shell = new GroovyShell();
        return shell.parse(hreq.getParameter("script")).run();
    }
}
