// expect: DF013
import android.app.Activity
import android.os.Bundle
import android.webkit.WebView

class DeepLinkActivity : Activity() {
    private lateinit var browser: WebView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        browser = WebView(this)
        val link = intent.data ?: return
        browser.loadUrl(link.toString())
    }
}
