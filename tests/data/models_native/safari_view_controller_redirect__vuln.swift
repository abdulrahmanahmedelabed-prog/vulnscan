// expect: DF008
import SafariServices
import UIKit

class LinkViewController: UIViewController {
    func application(_ app: UIApplication, open url: URL) -> Bool {
        let next = url.fragment ?? ""
        let browser = SFSafariViewController(url: URL(string: next)!)
        present(browser, animated: true)
        return true
    }
}
