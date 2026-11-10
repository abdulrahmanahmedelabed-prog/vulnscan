// expect: DF008
import io.ktor.server.application.*
import io.ktor.server.response.*
import io.ktor.server.routing.*

fun Application.auth() {
    routing {
        get("/login/done") {
            val next = call.request.queryParameters["next"] ?: "/"
            call.respondRedirect(next)
        }
    }
}
