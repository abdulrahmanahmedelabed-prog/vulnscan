// expect: DF010
import UIKit
import AsyncHTTPClient

class AppDelegate: UIResponder, UIApplicationDelegate {
    func application(_ app: UIApplication, open url: URL) -> Bool {
        let request = HTTPClientRequest(url: url.absoluteString)
        return true
    }
}
