// expect: DF005
import io.ktor.server.application.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import java.io.File

fun Application.docs() {
    routing {
        get("/docs/{name}") {
            val name = call.parameters["name"]
            call.respondText(File("/srv/docs", name).readText())
        }
    }
}
