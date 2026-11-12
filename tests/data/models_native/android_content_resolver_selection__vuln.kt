// expect: DF004
import android.app.Activity
import android.os.Bundle
import android.provider.ContactsContract

class ContactSearchActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val name = intent.getStringExtra("name")
        val cursor = contentResolver.query(
            ContactsContract.Contacts.CONTENT_URI, null,
            "display_name = '" + name + "'", null, null
        )
        cursor?.close()
    }
}
