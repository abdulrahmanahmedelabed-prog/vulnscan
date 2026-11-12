import org.springframework.web.bind.annotation.*

@RestController
class OwnerController {
    @GetMapping("/owners/{id}")
    fun show(@PathVariable id: String, @RequestParam q: String): String {
        return if (q.isEmpty()) "owners/list" else "owners/details"
    }

    @GetMapping("/echo")
    @ResponseBody
    fun echo(@RequestParam q: String): String {
        return if (q.isEmpty()) "empty" else "<p>" + q + "</p>"
    }
}
