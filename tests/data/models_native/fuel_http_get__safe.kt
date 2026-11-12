// expect-none: DF010
import com.github.kittinunf.fuel.httpGet
import io.ktor.server.application.*
import io.ktor.server.response.*
import io.ktor.server.routing.*

fun Route.preview() {
    get("/preview") {
        val q = call.request.queryParameters["q"] ?: return@get
        val (_, _, result) = "https://search.example.com/api".httpGet(listOf(Pair("q", q))).responseString()
        call.respondText(result.get())
    }
}
