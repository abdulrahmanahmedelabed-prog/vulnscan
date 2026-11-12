// expect-none: DF007 DF012 DF013
import UIKit
import WebKit

class EditorViewController: UIViewController {
    var webView: WKWebView!

    @IBAction func pasteTapped(_ sender: UIButton) {
        webView.evaluateJavaScript("editor.focus()")
    }
}
