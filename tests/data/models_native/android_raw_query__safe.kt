// expect-none: DF004
import android.app.Activity
import android.database.sqlite.SQLiteDatabase
import android.os.Bundle

class NoteActivity : Activity() {
    lateinit var db: SQLiteDatabase

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val title = intent.getStringExtra("title")
        val cursor = db.rawQuery("SELECT body FROM notes WHERE title = ?", arrayOf(title))
        cursor.close()
    }
}
