// expect-none: DF004
import android.app.Activity
import android.os.Bundle
import android.provider.MediaStore

class GalleryActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val order = intent.getStringExtra("order")
        val newestFirst = order == "newest"
        val sort = if (newestFirst) "date_added DESC" else "date_added ASC"
        val cursor = getContentResolver().query(
            MediaStore.Images.Media.EXTERNAL_CONTENT_URI, null, null, null, sort
        )
        cursor?.close()
    }
}
