// expect: DF006
import com.esotericsoftware.kryo.Kryo;
import com.esotericsoftware.kryo.io.Input;
import javax.servlet.http.HttpServletRequest;

public class Session {
    private Kryo kryo = new Kryo();

    public Object restore(HttpServletRequest hreq) throws Exception {
        Input input = new Input(hreq.getInputStream());
        return kryo.readClassAndObject(input);
    }
}
