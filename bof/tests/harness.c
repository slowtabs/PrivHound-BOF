#include "ph_graph.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void ph_file_emit(void *context, const char *data, int length) {
    FILE *output = (FILE *)context;
    if (!output || !data || length <= 0) return;
    fwrite(data, 1, (size_t)length, output);
    fflush(output);
}

int main(int argc, char **argv) {
    const char *path = NULL;
    FILE *output = stdout;
    PH_GRAPH graph;
    for (int i=1; i<argc; i++) {
        if ((strcmp(argv[i], "-o") == 0 || strcmp(argv[i], "--output") == 0) && i + 1 < argc) path = argv[++i];
        else if (strcmp(argv[i], "--validate-credentials") == 0 || strcmp(argv[i], "--spray-credentials") == 0) { }
        else if (strcmp(argv[i], "--help") == 0) {
            printf("Usage: privhound_harness.exe [-o output.ndjson] [--validate-credentials] [--spray-credentials]\n");
            return 0;
        }
    }
    if (path) {
        output = fopen(path, "wb");
        if (!output) { fprintf(stderr, "Could not open output: %s\n", path); return 2; }
    }
    ph_graph_init(&graph, ph_file_emit, output);
    for (int i=1; i<argc; i++) {
        if (strcmp(argv[i], "--validate-credentials") == 0) graph.validate_credentials = TRUE;
        if (strcmp(argv[i], "--spray-credentials") == 0) { graph.validate_credentials = TRUE; graph.spray_credentials = TRUE; }
    }
    ph_collect(&graph);
    fprintf(stderr, "nodes=%u edges=%u findings=%u errors=%u\n", graph.node_count, graph.edge_count, graph.finding_count, graph.error_count);
    ph_graph_dispose(&graph);
    if (path) fclose(output);
    return graph.error_count ? 1 : 0;
}

