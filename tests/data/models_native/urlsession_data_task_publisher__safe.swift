// expect-none: DF010
import Combine
import UIKit

class FeedViewController: UIViewController, UITextFieldDelegate {
    var subscription: AnyCancellable?

    func textFieldShouldReturn(_ textField: UITextField) -> Bool {
        subscription = URLSession.shared.dataTaskPublisher(for: URL(string: "https://feeds.example.com/top.json")!)
            .sink(receiveCompletion: { _ in }, receiveValue: { _ in })
        return true
    }
}
