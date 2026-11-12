// expect-none: DF013
import android.app.Activity
import android.os.Bundle
import android.webkit.WebView

class CheckoutActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val checkoutWebView = WebView(this)
        val cart = intent.getStringExtra("cart") ?: return
        checkoutWebView.postUrl("https://pay.example.com/checkout", cart.length.toString().toByteArray())
    }
}
