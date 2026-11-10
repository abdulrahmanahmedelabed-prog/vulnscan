// expect: DF012
import org.springframework.expression.spel.standard.SpelExpressionParser;
import javax.servlet.http.HttpServletRequest;

public class Expr {
    public Object eval(HttpServletRequest hreq) {
        SpelExpressionParser parser = new SpelExpressionParser();
        return parser.parseRaw(hreq.getHeader("X-Expr")).getValue();
    }
}
