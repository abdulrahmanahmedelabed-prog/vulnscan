// expect: DF002
import Foundation

let target = CommandLine.arguments[1]
let job = Process.launchedProcess(launchPath: "/bin/sh", arguments: ["-c", "ping -c 1 " + target])
job.waitUntilExit()
