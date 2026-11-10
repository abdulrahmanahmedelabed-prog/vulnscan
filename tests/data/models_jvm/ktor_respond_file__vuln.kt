// expect: DF005
import io.ktor.server.application.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import java.io.File

val staticRoot = File("/srv/static")

fun Application.files() {
    routing {
        get("/files") {
            call.respondFile(staticRoot, call.request.queryParameters["f"] ?: "index.html")
        }
    }
}
