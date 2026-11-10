// expect-none: DF012
import io.vertx.ext.web.RoutingContext;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;

public class Calc {
    public void handle(RoutingContext routingContext) throws Exception {
        int n = Integer.parseInt(routingContext.request().getFormAttribute("n"));
        ScriptEngine jsEngine = new ScriptEngineManager().getEngineByName("js");
        routingContext.response().end(String.valueOf(jsEngine.eval("1 + " + n)));
    }
}
