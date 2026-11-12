// expect-none: DF002
import Foundation
import ShellOut

let repository = CommandLine.arguments[1]
let output = try shellOut(to: "git status --short")
print(output.count + repository.count)
