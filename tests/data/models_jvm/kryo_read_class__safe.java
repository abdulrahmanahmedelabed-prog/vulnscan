// expect-none: DF006
import com.esotericsoftware.kryo.Kryo;
import com.esotericsoftware.kryo.io.Input;
import javax.servlet.http.HttpServletRequest;

public class Session {
    private Kryo kryo = new Kryo();
    private static final byte[] DEFAULTS = new byte[] {1, 0};

    public Object restore(HttpServletRequest hreq) throws Exception {
        Input input = new Input(DEFAULTS);
        return kryo.readClassAndObject(input);
    }
}
