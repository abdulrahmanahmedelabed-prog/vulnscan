// expect: DF006
import org.yaml.snakeyaml.Yaml;
import javax.servlet.http.HttpServletRequest;

public class Config {
    public Object read(HttpServletRequest hreq) throws Exception {
        Yaml yaml = new Yaml();
        return yaml.loadAs(hreq.getReader(), java.util.Map.class);
    }
}
