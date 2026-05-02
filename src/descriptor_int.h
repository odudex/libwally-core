#ifndef WALLY_DESCRIPTOR_INT_H
#define WALLY_DESCRIPTOR_INT_H

#include <stdint.h>
#include <stddef.h>

/* A node in a parsed miniscript expression */
typedef struct ms_node_t {
    struct ms_node_t *next;
    struct ms_node_t *child;
    struct ms_node_t *parent;
    uint32_t kind;
    uint32_t type_properties;
    int64_t number;
    const char *child_path;
    const char *data;
    uint32_t data_len;
    uint32_t child_path_len;
    char wrapper_str[12];
    unsigned short flags; /* WALLY_MS_IS_ flags */
    unsigned char builtin;
} ms_node;

typedef struct wally_descriptor ms_ctx;

/* Built-in miniscript expressions */
typedef int (*node_verify_fn_t)(ms_ctx *ctx, ms_node *node);
typedef int (*node_gen_fn_t)(ms_ctx *ctx, ms_node *node,
                             unsigned char *script, size_t script_len, size_t *written);

struct ms_builtin_t {
    const char *name;
    const uint32_t name_len;
    const uint32_t kind;
    const uint32_t type_properties;
    const uint32_t child_count; /* Number of expected children */
    const node_verify_fn_t verify_fn;
    const node_gen_fn_t generate_fn;
};

extern const struct ms_builtin_t g_builtins[];

#endif /* WALLY_DESCRIPTOR_INT_H */
