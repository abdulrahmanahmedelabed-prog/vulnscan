// expect-none: DF008
import AVFoundation
import UIKit

class ScannerViewController: UIViewController, AVCaptureMetadataOutputObjectsDelegate {
    func handle(readableObject: AVMetadataMachineReadableCodeObject) {
        let scanned = readableObject.stringValue ?? ""
        guard scanned == "TICKET" else { return }
        present(SFSafariViewController(url: URL(string: "https://tickets.example.com/scan")!), animated: true)
    }
}
