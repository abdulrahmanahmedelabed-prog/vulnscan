// expect-none: DF005
import UIKit
import WebKit

class ReaderViewController: UIViewController {
    var webView: WKWebView!

    func application(_ app: UIApplication, open url: URL) -> Bool {
        let page = Bundle.main.url(forResource: "reader", withExtension: "html")!
        webView.loadFileURL(page, allowingReadAccessTo: page.deletingLastPathComponent())
        return true
    }
}
