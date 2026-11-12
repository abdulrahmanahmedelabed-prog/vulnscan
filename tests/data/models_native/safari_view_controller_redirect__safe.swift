// expect-none: DF008
import SafariServices
import UIKit

class LinkViewController: UIViewController {
    func application(_ app: UIApplication, open url: URL) -> Bool {
        let browser = SFSafariViewController(url: URL(string: "https://help.example.com/")!)
        present(browser, animated: true)
        return true
    }
}
