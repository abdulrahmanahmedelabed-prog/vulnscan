// expect-none: DF013
import UIKit
import WebKit

class NoteViewController: UIViewController {
    var webView: WKWebView!

    func application(_ app: UIApplication, open url: URL) -> Bool {
        let origin = URLRequest(url: URL(string: "https://notes.example.com/")!)
        webView.loadSimulatedRequest(origin, responseHTML: "<h1>Notes</h1>")
        return true
    }
}
