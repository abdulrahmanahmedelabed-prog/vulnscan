// expect-none: DF013
import android.app.Activity
import android.os.Bundle

class Router {
    fun loadUrl(route: String) = println("navigate to $route")
}

class MainActivity : Activity() {
    private val router = Router()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val route = intent.getStringExtra("route") ?: "home"
        router.loadUrl(route)
    }
}
