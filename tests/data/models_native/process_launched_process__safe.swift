// expect-none: DF002
import Foundation

let target = CommandLine.arguments[1]
let job = Process.launchedProcess(launchPath: "/bin/sh", arguments: ["-c", "ping -c 1 127.0.0.1"])
job.waitUntilExit()
print(target.count)
