// expect: DF010
import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.server.application.*
import io.ktor.server.response.*
import io.ktor.server.routing.*

val client = HttpClient()

fun Route.relay() {
    post("/relay") {
        val callback = call.request.header("X-Callback-Url") ?: return@post
        call.respondText(client.get(callback).bodyAsText())
    }
}
