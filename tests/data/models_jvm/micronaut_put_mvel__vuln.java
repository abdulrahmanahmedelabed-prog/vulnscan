// expect: DF012
import io.micronaut.http.annotation.Put;
import io.micronaut.http.annotation.Body;
import org.mvel2.MVEL;

public class Rules {
    @Put("/rule")
    public Object apply(@Body String rule) {
        return MVEL.eval(rule);
    }
}
