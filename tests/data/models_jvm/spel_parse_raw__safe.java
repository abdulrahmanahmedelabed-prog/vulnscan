// expect-none: DF012
import org.springframework.expression.spel.standard.SpelExpressionParser;
import javax.servlet.http.HttpServletRequest;

public class Expr {
    public Object eval(HttpServletRequest hreq) {
        SpelExpressionParser parser = new SpelExpressionParser();
        String header = hreq.getHeader("X-Expr");
        return parser.parseRaw("'constant'.length()").getValue();
    }
}
