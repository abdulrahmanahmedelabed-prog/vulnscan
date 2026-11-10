// expect: DF012
import groovy.util.Eval;
import javax.servlet.http.HttpServletRequest;

public class Calc {
    public Object calc(HttpServletRequest hreq) {
        // Eval.x(value, expression): the expression (argument 1) is evaluated as Groovy code
        return Eval.x(10, hreq.getParameter("expr"));
    }
}
