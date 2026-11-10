// expect: DF012
import io.vertx.ext.web.RoutingContext;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;

public class Calc {
    public void handle(RoutingContext routingContext) throws Exception {
        String formula = routingContext.request().getFormAttribute("formula");
        ScriptEngine jsEngine = new ScriptEngineManager().getEngineByName("js");
        routingContext.response().end(String.valueOf(jsEngine.eval(formula)));
    }
}
