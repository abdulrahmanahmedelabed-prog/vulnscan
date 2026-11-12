// expect: DF005
import UIKit
import WebKit

class ReaderViewController: UIViewController {
    var webView: WKWebView!

    func application(_ app: UIApplication, open url: URL) -> Bool {
        let page = URL(fileURLWithPath: url.path)
        webView.loadFileURL(page, allowingReadAccessTo: page)
        return true
    }
}
