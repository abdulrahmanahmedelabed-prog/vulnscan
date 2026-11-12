// expect-none: DF010
import com.github.kittinunf.fuel.Fuel
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

@RestController
class WebhookController {
    @GetMapping("/webhook/test")
    fun test(@RequestParam callback: String): String {
        val (_, response, _) = Fuel.post("https://hooks.example.com/test", listOf(Pair("callback", callback))).response()
        return if (response.statusCode == 200) "sent" else "failed"
    }
}
