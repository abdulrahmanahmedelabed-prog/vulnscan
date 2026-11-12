// expect: DF004
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.web.reactive.function.server.ServerRequest
import org.springframework.web.reactive.function.server.ServerResponse
import org.springframework.web.reactive.function.server.bodyValueAndAwait
import org.springframework.web.reactive.function.server.queryParamOrNull

class ProductHandler(private val jdbc: JdbcTemplate) {
    suspend fun list(r: ServerRequest): ServerResponse {
        val sort = r.queryParamOrNull("sort") ?: "id"
        val rows = jdbc.queryForList("SELECT id, name FROM products ORDER BY $sort")
        return ServerResponse.ok().bodyValueAndAwait(rows)
    }
}
