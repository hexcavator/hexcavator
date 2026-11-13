/* Pointers for Hexcavator's Mach-O test inputs (see build.cmd): rebases of
   its own objects' addresses (a gap in `table`, and `far` past a page's
   reach of the others), and a bind of an import's (`imported`, which dyld
   would find: the dylib is linked with -undefined dynamic_lookup). Linked
   with chained fixups, and with the older rebase and bind opcodes. */

static int a, b, c;
static void f(void) {}
extern int imported;

int *table[] = {&a, &b, &c, &a, 0, &b, &c};
void (*handlers[])(void) = {f, f};
long gap[1100] = {1};
int *far = &c;
int *outside = &imported;
