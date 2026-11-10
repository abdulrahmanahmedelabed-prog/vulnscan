// expect-none: DF005
import kotlin.io.path.Path
import kotlin.io.path.readText
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

@RestController
class Notes {
    @GetMapping("/notes")
    fun note(@RequestParam id: String): String = Path("/srv/notes", id.toInt().toString() + ".txt").readText()
}
