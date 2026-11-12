// expect-none: DF005
import Vapor

func routes(_ app: Application) throws {
    app.get("logs", ":name") { req -> String in
        let day = Int(req.parameters.get("name")!) ?? 0
        let handle = FileHandle(forReadingAtPath: "/var/log/app/day-\(day).log")
        let data = handle?.readDataToEndOfFile() ?? Data()
        return "\(data.count)"
    }
}
