// expect: DF013
import UIKit
import WebKit

class NoteViewController: UIViewController {
    var webView: WKWebView!

    func application(_ app: UIApplication, open url: URL) -> Bool {
        let title = url.fragment ?? ""
        let origin = URLRequest(url: URL(string: "https://notes.example.com/")!)
        webView.loadSimulatedRequest(origin, responseHTML: "<h1>" + title + "</h1>")
        return true
    }
}
