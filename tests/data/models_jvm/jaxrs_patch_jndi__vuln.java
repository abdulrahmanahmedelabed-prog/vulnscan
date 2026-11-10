// expect: DF012
import javax.naming.InitialContext;
import javax.ws.rs.PATCH;
import javax.ws.rs.QueryParam;

public class Lookup {
    @PATCH
    public Object resolve(@QueryParam("name") String name) throws Exception {
        InitialContext ctx = new InitialContext();
        return ctx.lookup(name);
    }
}
