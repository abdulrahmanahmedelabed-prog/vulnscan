// expect-none: DF013
import android.os.Bundle
import android.webkit.WebView
import androidx.appcompat.app.AppCompatActivity

class HelpActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val webView = WebView(this)
        setContentView(webView)
        val page = intent.getStringExtra("page") ?: return
        val topic = page.toIntOrNull() ?: 0
        webView.loadUrl("https://help.example.com/topics/$topic")
    }
}
