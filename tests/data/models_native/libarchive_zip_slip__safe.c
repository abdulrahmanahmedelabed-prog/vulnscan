// expect-none: DF005
#include <archive.h>
#include <archive_entry.h>
#include <fcntl.h>
#include <glib.h>
#include <libgen.h>

void extract(struct archive *a, const char *outdir) {
    struct archive_entry *entry;
    while (archive_read_next_header(a, &entry) == ARCHIVE_OK) {
        char *leaf = basename(archive_entry_pathname(entry));
        char *dest = g_build_filename(outdir, leaf, NULL);
        int fd = open(dest, O_WRONLY | O_CREAT, 0644);
        archive_read_data_into_fd(a, fd);
        g_free(dest);
    }
}
