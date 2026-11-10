// expect: DF005
import kotlin.io.path.Path
import kotlin.io.path.readText
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

@RestController
class Notes {
    @GetMapping("/notes")
    fun note(@RequestParam file: String): String = Path("/srv/notes", file).readText()
}
