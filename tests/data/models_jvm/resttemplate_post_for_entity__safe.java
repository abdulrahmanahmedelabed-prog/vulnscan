// expect-none: DF010
import org.springframework.web.client.RestTemplate;
import javax.servlet.http.HttpServletRequest;

public class Proxy {
    private RestTemplate restTemplate = new RestTemplate();

    public Object forward(HttpServletRequest hreq) {
        return restTemplate.postForEntity("https://api.example.com/events", hreq.getParameter("event"), String.class);
    }
}
