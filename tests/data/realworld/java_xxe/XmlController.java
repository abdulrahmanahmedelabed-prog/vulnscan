import javax.servlet.http.HttpServletRequest;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.StringReader;
import org.dom4j.io.SAXReader;
import org.xml.sax.InputSource;
import org.springframework.web.bind.annotation.*;

@RestController
public class XmlController {
    @PostMapping("/dom/vuln")
    public String domVuln(HttpServletRequest request) throws Exception {
        String body = request.getParameter("xml");
        DocumentBuilder db = DocumentBuilderFactory.newInstance().newDocumentBuilder();
        db.parse(new InputSource(new StringReader(body)));
        return "ok";
    }

    @PostMapping("/dom/sec")
    public String domSec(HttpServletRequest request) throws Exception {
        String body = request.getParameter("xml");
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        DocumentBuilder db = dbf.newDocumentBuilder();
        db.parse(new InputSource(new StringReader(body)));
        return "ok";
    }

    @PostMapping("/sax/vuln")
    public String saxVuln(HttpServletRequest request) throws Exception {
        String body = request.getParameter("xml");
        SAXReader reader = new SAXReader();
        reader.read(new InputSource(new StringReader(body)));
        return "ok";
    }
}
