// expect: DF006
import org.apache.commons.lang3.SerializationUtils;
import javax.servlet.http.HttpServletRequest;
import java.util.Base64;

public class Cart {
    public Object load(HttpServletRequest hreq) {
        byte[] raw = Base64.getDecoder().decode(hreq.getHeader("X-Cart"));
        return SerializationUtils.deserialize(raw);
    }
}
