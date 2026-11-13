// Pointers the loader relocates (see build.cmd): in a shared object, each
// is a relative relocation, which -z pack-relative-relocs packs as RELR:
// an address, then bitmaps of the words after it. The gap in `table` makes
// a bitmap with a hole; `far` is past one bitmap's reach.

static int a, b, c;
static void f(void) {}

int *table[] = {&a, &b, &c, &a, 0, &b, &c};
void (*handlers[])(void) = {f, f};
long gap[70] = {1};
int *far = &c;
