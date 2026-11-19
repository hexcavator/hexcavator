/* Compiled three times (USE=use_a, use_b, use_c): the header's lut and
   this file's tag are each one definition copied; state, zeros, and the
   header's hcounter are variables, each object's own. */
#include "dup.h"
extern volatile int sink;
static int state;
static int zeros[16];
static const char tag[24] = "the same text in each";
int USE(int i) {
  state += i;
  zeros[i & 15]++;
  hcounter++;
  return lut[i & 31] + tag[i & 15] + state + zeros[3] + hcounter;
}
