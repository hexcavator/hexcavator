/* Variables named and valued as dup.c's, but defined apart: not copies of
   one definition. */
extern volatile int sink;
static int state;
static const char tag[24] = "the same text in each";
int use_other(int i) {
  state += i;
  return tag[i & 15] + state;
}
