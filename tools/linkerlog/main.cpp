#include <stdio.h>
#include <vector>
int unused_function(int x) { return x * 3; }
int same_a(int x) { return x + 1; }
int same_b(int x) { return x + 1; }
int main(int argc, char**) {
    std::vector<int> v{1, 2, 3};
    printf("%d %d\n", same_a(argc), same_b(argc) + (int)v.size());
    return 0;
}
