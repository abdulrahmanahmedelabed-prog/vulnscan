// expect-none: DF002
import Foundation
import Kitura

let router = Router()
router.get("/resize") { request, response, next in
    let size = Int(request.queryParameters["size"] ?? "") ?? 64
    let job = Process.launchedProcess(launchPath: "/usr/bin/mogrify", arguments: ["-resize", "\(size)", "in.png"])
    job.waitUntilExit()
    next()
}
