// expect: DF008
import AVFoundation
import UIKit

class ScannerViewController: UIViewController, AVCaptureMetadataOutputObjectsDelegate {
    func handle(readableObject: AVMetadataMachineReadableCodeObject) {
        let scanned = readableObject.stringValue ?? ""
        present(SFSafariViewController(url: URL(string: scanned)!), animated: true)
    }
}
