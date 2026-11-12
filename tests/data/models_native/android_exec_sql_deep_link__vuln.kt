// expect: DF004
import android.app.Activity
import android.database.sqlite.SQLiteDatabase
import android.os.Bundle

class UnsubscribeActivity : Activity() {
    lateinit var database: SQLiteDatabase

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val uri = intent.data ?: return
        val topic = uri.getQueryParameter("topic")
        database.execSQL("DELETE FROM subscriptions WHERE topic = '$topic'")
    }
}
