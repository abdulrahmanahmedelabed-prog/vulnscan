// expect: DF002
import Foundation
import Kitura

let router = Router()
router.get("/resize") { request, response, next in
    let size = request.queryParameters["size"] ?? ""
    let job = Process.launchedProcess(launchPath: "/bin/sh", arguments: ["-c", "mogrify -resize " + size + " in.png"])
    job.waitUntilExit()
    next()
}
