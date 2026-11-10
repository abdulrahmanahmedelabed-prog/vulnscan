// expect-none: DF010 DF005
import io.ktor.server.application.*
import io.ktor.server.response.*
import io.ktor.server.routing.*

val cache = mutableMapOf<String, String>()

fun Application.lookup() {
    routing {
        get("/cache") {
            val key = call.request.queryParameters["key"] ?: ""
            call.respondText(cache.get(key) ?: "miss")
        }
    }
}
