#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

typedef struct {
    const char *file;
    long lines;
    long words;
    long bytes;
} Stats;

static Stats stat_file(const char *path) {
    Stats s = {path, 0, 0, 0};

    FILE *f = fopen(path, "rb");
    if (!f) {
        perror(path);
        return s;
    }

    int in_word = 0;
    int c;
    while ((c = fgetc(f)) != EOF) {
        s.bytes++;
        if (c == '\n') s.lines++;
        if (isspace(c)) {
            in_word = 0;
        } else if (!in_word) {
            in_word = 1;
            s.words++;
        }
    }

    fclose(f);
    return s;
}

static void print_row(Stats s) {
    printf("%8ld %8ld %8ld  %s\n", s.lines, s.words, s.bytes, s.file);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "usage: wc <file> [file ...]\n");
        return 1;
    }

    int nfiles = argc - 1;
    Stats *stats = malloc(nfiles * sizeof(Stats));
    if (!stats) { perror("malloc"); return 1; }

    for (int i = 0; i < nfiles; i++) {
        stats[i] = stat_file(argv[i + 1]);
        print_row(stats[i]);
    }

    if (nfiles > 1) {
        Stats total = {"total", 0, 0, 0};
        for (int i = 0; i < nfiles; i++) {
            total.lines += stats[i].lines;
            total.words += stats[i].words;
            total.bytes += stats[i].bytes;
        }
        print_row(total);
    }

    free(stats);
    return 0;
}
