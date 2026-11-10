// expect: DF008
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import java.net.URI;

public class Login {
    public Object done(ServerRequest serverRequest) {
        URI next = URI.create(serverRequest.queryParam("next").orElse("/"));
        return ServerResponse.temporaryRedirect(next).build();
    }
}
