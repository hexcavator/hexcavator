// The source lines test program (see build.cmd): code from a header, and
// inline sites (one nested in another).
#include <stdio.h>

#include "lines.h"

__declspec(noinline) int first(int x) { return square(x) + 1; }

__declspec(noinline) int second(int x) { return square(x + 1) * 3; }

__declspec(noinline) int third(int a, int b) { return sum_of_squares(a, b) - 7; }

int main(int argc, char**) {
    printf("%d %d %d %d %f\n", first(argc), second(argc), third(argc, argc + 2), twice(argc), twice(argc * 1.5));
    return 0;
}
