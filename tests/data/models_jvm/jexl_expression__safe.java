// expect-none: DF012
import org.apache.commons.jexl3.JexlBuilder;
import org.apache.commons.jexl3.JexlEngine;
import org.apache.commons.jexl3.MapContext;
import javax.servlet.http.HttpServletRequest;

public class Filters {
    public Object eval(HttpServletRequest hreq) {
        JexlEngine jexl = new JexlBuilder().create();
        MapContext jc = new MapContext();
        jc.set("q", hreq.getParameter("filter"));
        return jexl.createExpression("q.length() > 3");
    }
}
