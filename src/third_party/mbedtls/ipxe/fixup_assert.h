/*
 * Force-include before mbedTLS sources to fix static_assert arity.
 *
 * iPXE's <assert.h> defines static_assert(x) as a 1-arg macro.
 * mbedTLS common.h checks defined(static_assert) and, if true,
 * calls it with 2 args.  By including <assert.h> here and then
 * undefining static_assert, the check in common.h sees it as
 * undefined and falls through to a safe no-op.
 */
#include <assert.h>
#undef static_assert
