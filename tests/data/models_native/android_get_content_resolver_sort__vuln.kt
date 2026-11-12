// expect: DF004
import android.app.Activity
import android.os.Bundle
import android.provider.MediaStore

class GalleryActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val order = intent.getStringExtra("order")
        val cursor = getContentResolver().query(
            MediaStore.Images.Media.EXTERNAL_CONTENT_URI, null, null, null, order
        )
        cursor?.close()
    }
}
