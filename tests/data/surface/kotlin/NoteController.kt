package com.acme.notes

import org.springframework.security.access.annotation.Secured
import org.springframework.web.bind.annotation.*
import java.net.URL

@RestController
@RequestMapping("/notes")
class NoteController(private val repo: NoteRepository) {

    @GetMapping("/{id}")
    fun one(@PathVariable id: Long): Note = repo.findById(id)

    @GetMapping("/preview")
    fun preview(@RequestParam url: String): String {
        return URL(url).readText()
    }

    @Secured("ROLE_EDITOR")
    @PutMapping("/{id}")
    fun update(@PathVariable id: Long, @RequestBody note: NoteDto): Note {
        return repo.save(id, note)
    }
}
