// expect-none: DF006
import org.apache.commons.lang3.SerializationUtils;
import javax.servlet.http.HttpServletRequest;

public class Cart {
    public Object copy(HttpServletRequest hreq, java.io.Serializable cart) {
        String id = hreq.getHeader("X-Cart");
        return SerializationUtils.deserialize(SerializationUtils.serialize(cart));
    }
}
