// expect-none: DF004
import FMDB
import UIKit

class ImportViewController: UIViewController, UITextFieldDelegate {
    var store: FMDatabase!

    func textFieldDidEndEditing(_ textField: UITextField) {
        let label = textField.text ?? ""
        try? store.executeUpdate("INSERT INTO labels (name) VALUES (?)", values: [label])
    }
}
