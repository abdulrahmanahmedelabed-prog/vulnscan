// expect: DF005
import android.app.Service
import android.content.Intent
import android.os.IBinder
import java.io.File

class ExportService : Service() {
    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val path = intent?.extras?.getString("path") ?: return START_NOT_STICKY
        File(filesDir, path).writeText("exported")
        return START_NOT_STICKY
    }
}
