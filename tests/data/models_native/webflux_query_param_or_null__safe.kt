// expect-none: DF004
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.web.reactive.function.server.ServerRequest
import org.springframework.web.reactive.function.server.ServerResponse
import org.springframework.web.reactive.function.server.bodyValueAndAwait
import org.springframework.web.reactive.function.server.queryParamOrNull

class ProductHandler(private val jdbc: JdbcTemplate) {
    suspend fun list(r: ServerRequest): ServerResponse {
        val name = r.queryParamOrNull("name") ?: ""
        val rows = jdbc.queryForList("SELECT id, name FROM products WHERE name = ?", name)
        return ServerResponse.ok().bodyValueAndAwait(rows)
    }
}
