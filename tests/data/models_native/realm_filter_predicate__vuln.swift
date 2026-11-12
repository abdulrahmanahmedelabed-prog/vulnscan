// expect: DF004
import RealmSwift
import UIKit

class SearchViewController: UIViewController, UISearchBarDelegate {
    func searchBarSearchButtonClicked(_ searchBar: UISearchBar) {
        let term = searchBar.text ?? ""
        let realm = try! Realm()
        let hits = realm.objects(Contact.self).filter("name CONTAINS '\(term)'")
        show(hits)
    }
}
