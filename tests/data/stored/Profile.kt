import javax.persistence.Entity
import org.springframework.web.bind.annotation.*

@Entity
class Profile(var bio: String = "", var city: String = "")

@RestController
class ProfileController(private val profileRepository: ProfileRepository) {
    @PostMapping("/p")
    fun save(@RequestParam bio: String) {
        val p = Profile()
        p.setBio(bio)
        p.setCity("Gaza")
        profileRepository.save(p)
    }
    @GetMapping("/p")
    fun show(): String {
        val p = profileRepository.findById(1)
        Runtime.getRuntime().exec(p.getBio())
        Runtime.getRuntime().exec(p.getCity())
        return "ok"
    }
}
