// expect: DF002
import Foundation
import ShellOut

let repository = CommandLine.arguments[1]
let output = try shellOut(to: "git clone \(repository) checkout")
print(output.count)
