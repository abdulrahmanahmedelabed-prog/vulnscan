// expect: DF013
import android.app.Activity
import android.os.Bundle
import android.webkit.WebView

class CheckoutActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val checkoutWebView = WebView(this)
        val gateway = intent.getStringExtra("gateway") ?: return
        checkoutWebView.postUrl(gateway, "cart=1".toByteArray())
    }
}
