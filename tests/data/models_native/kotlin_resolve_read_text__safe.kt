// expect-none: DF005
import io.ktor.server.application.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import java.io.File

val docsRoot = File("/srv/docs")

fun Route.docs() {
    get("/docs") {
        val name = call.request.queryParameters["name"] ?: "index.md"
        if (!name.matches(Regex("[a-z0-9_-]+\\.md"))) {
            return@get
        }
        call.respondText(docsRoot.resolve(name).readText())
    }
}
