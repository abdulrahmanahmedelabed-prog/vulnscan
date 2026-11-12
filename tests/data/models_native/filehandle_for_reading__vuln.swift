// expect: DF005
import Vapor

func routes(_ app: Application) throws {
    app.get("logs", ":name") { req -> String in
        let name = req.parameters.get("name")!
        let handle = FileHandle(forReadingAtPath: "/var/log/app/" + name)
        let data = handle?.readDataToEndOfFile() ?? Data()
        return "\(data.count)"
    }
}
