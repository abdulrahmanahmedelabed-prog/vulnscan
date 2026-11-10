// expect-none: DF004
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.web.bind.annotation.DeleteMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.RestController

@RestController
class Items(private val jdbcTemplate: JdbcTemplate) {
    @DeleteMapping("/items/{name}")
    fun delete(@PathVariable name: String) {
        jdbcTemplate.update("DELETE FROM items WHERE name = ?", name)
    }
}
