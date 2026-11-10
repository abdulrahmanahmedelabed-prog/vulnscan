// expect-none: DF010
import io.ktor.client.*
import io.ktor.client.request.*
import io.ktor.server.application.*
import io.ktor.server.routing.*

val client = HttpClient()

fun Application.preview() {
    routing {
        get("/preview") {
            val target = call.request.queryParameters["url"]!!
            client.get("https://preview.example.com/render")
        }
    }
}
