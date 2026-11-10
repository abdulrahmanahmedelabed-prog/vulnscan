// expect-none: DF012
import io.micronaut.http.annotation.Put;
import io.micronaut.http.annotation.Body;
import org.mvel2.MVEL;
import java.util.Map;

public class Rules {
    @Put("/rule")
    public Object apply(@Body String rule) {
        return MVEL.eval("price * qty", Map.of("price", 2, "qty", rule.length()));
    }
}
