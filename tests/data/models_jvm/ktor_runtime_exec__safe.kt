// expect-none: DF002 DF003
import io.ktor.server.application.*
import io.ktor.server.response.*
import io.ktor.server.routing.*

fun Application.tools() {
    routing {
        get("/ping") {
            val host = call.request.queryParameters["host"]
            val proc = Runtime.getRuntime().exec(arrayOf("uptime"))
            call.respondText(proc.inputStream.bufferedReader().readText())
        }
    }
}
