#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>


#define NUM_PROG 3
#define MAX_HIST 17

void print_histogram(__u64 arr[]) {
    int star_col = 50;
    printf("usecs           : ");
    printf("count      | ");
    printf("distribution\n");
    for (int i = 0; i < MAX_HIST; i++) {
        int lb = i ? 1 << i : 0;
        int ub = (1 << (i + 1)) - 1;
        printf("%5d -> %-7d: %-10llu | ", lb, ub, arr[i]);
        for (int j = 0; j < arr[i]; j++)
            printf("*");
        for (int j = arr[i]; j < star_col; j++)
            printf(" ");
        printf("|\n");
    }
    printf("\n");
}

int main(int argc, char **argv) {

    if (argc < 2) {
        fprintf(stderr, "ERROR: no measurement period supplied");
        return 1;
    }
    int period = atoi(argv[1]);

    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *links[NUM_PROG];
    int prog_fd;

    // Load and verify BPF application
    fprintf(stderr, "Loading BPF code in memory\n");
    obj = bpf_object__open_file("iolatency.bpf.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "ERROR: opening BPF object file failed\n");
        return 1;
    }

    // Load BPF program
    fprintf(stderr, "Loading and verifying the code in the kernel\n");
    if (bpf_object__load(obj)) {
        fprintf(stderr, "ERROR: loading BPF object file failed\n");
        return 1;
    }

    // Attach BPF program
    char *prog_names[] = {"block_rq_issue",
                          "block_rq_insert",
                          "block_rq_complete"};
    for (int i = 0; i < NUM_PROG; i++) {
        printf("Attaching program %s\n", prog_names[i]);
        prog = bpf_object__find_program_by_name(obj, prog_names[i]);
        if (libbpf_get_error(prog)) {
            fprintf(stderr, "ERROR: finding BPF program failed\n");
            return 1;
        }
        prog_fd = bpf_program__fd(prog);
        if (prog_fd < 0) {
            fprintf(stderr, "ERROR: getting BPF program FD failed\n");
            return 1;
        }
        links[i] = bpf_program__attach(prog);
        if (libbpf_get_error(links[i])) {
            fprintf(stderr, "ERROR: Attaching BPF program failed\n");
            return 1;
        }
    }

    struct bpf_map *hist_map;
    hist_map = bpf_object__find_map_by_name(obj, "hist");
    if (libbpf_get_error(hist_map)) {
        fprintf(stderr, "ERROR: finding BPF map failed\n");
        return 1;
    }
    int map_fd = bpf_map__fd(hist_map);

    // Output stats
    __u64 counts[MAX_HIST] = {0};
    while (1) {
        sleep(period);
        __u64 *curr_key = NULL;
        __u64 next_key;
        __u64 value;
        while (bpf_map_get_next_key(map_fd, curr_key, &next_key) == 0) {
            bpf_map_lookup_elem(map_fd, &next_key, &value);
            counts[next_key] = value;
            curr_key = &next_key;
            bpf_map_delete_elem(map_fd, &next_key);
        }
        print_histogram(counts);
    }

    // Cleanup
    for (int i = 0; i < NUM_PROG; i++) {
        bpf_link__destroy(links[i]);
    }
    bpf_object__close(obj);

    return 0;
}
