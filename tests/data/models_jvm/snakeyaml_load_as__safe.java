// expect-none: DF006
import org.yaml.snakeyaml.Yaml;
import javax.servlet.http.HttpServletRequest;

public class Config {
    public Object read(HttpServletRequest hreq) throws Exception {
        Yaml yaml = new Yaml();
        String profile = hreq.getParameter("profile");
        return yaml.loadAs(getClass().getResourceAsStream("/defaults.yml"), java.util.Map.class);
    }
}
