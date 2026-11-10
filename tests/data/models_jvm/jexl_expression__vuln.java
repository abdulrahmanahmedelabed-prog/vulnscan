// expect: DF012
import org.apache.commons.jexl3.JexlBuilder;
import org.apache.commons.jexl3.JexlEngine;
import javax.servlet.http.HttpServletRequest;

public class Filters {
    public Object eval(HttpServletRequest hreq) {
        JexlEngine jexl = new JexlBuilder().create();
        return jexl.createExpression(hreq.getParameter("filter")).evaluate(null);
    }
}
