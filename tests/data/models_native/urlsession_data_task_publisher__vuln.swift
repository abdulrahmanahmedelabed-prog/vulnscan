// expect: DF010
import Combine
import UIKit

class FeedViewController: UIViewController, UITextFieldDelegate {
    var subscription: AnyCancellable?

    func textFieldShouldReturn(_ textField: UITextField) -> Bool {
        let address = textField.text ?? ""
        subscription = URLSession.shared.dataTaskPublisher(for: URL(string: address)!)
            .sink(receiveCompletion: { _ in }, receiveValue: { _ in })
        return true
    }
}
