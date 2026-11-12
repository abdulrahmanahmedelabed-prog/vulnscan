// expect-none: DF004
import CoreData
import Vapor

func routes(_ app: Application, context: NSManagedObjectContext) throws {
    app.get("notes") { req -> String in
        let title = try req.query.get(String.self, at: "title")
        let request = NSFetchRequest<NSManagedObject>(entityName: "Note")
        request.predicate = NSPredicate(format: "title == %@", title)
        return "\(try context.count(for: request))"
    }
}
