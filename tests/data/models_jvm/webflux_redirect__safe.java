// expect-none: DF008
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import java.net.URI;

public class Login {
    public Object done(ServerRequest serverRequest) {
        String next = serverRequest.queryParam("next").orElse("/");
        return ServerResponse.temporaryRedirect(URI.create("/home")).build();
    }
}
