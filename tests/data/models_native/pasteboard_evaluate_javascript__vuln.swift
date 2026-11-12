// expect: DF007
import UIKit
import WebKit

class EditorViewController: UIViewController {
    var webView: WKWebView!

    @IBAction func pasteTapped(_ sender: UIButton) {
        let clip = UIPasteboard.general.string ?? ""
        webView.evaluateJavaScript("editor.insert('" + clip + "')")
    }
}
