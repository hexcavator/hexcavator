/* A second compile unit for Hexcavator's DWARF tests: functions in their own
   sections (so the unit's code is not contiguous), and data. */

int second_table[32] = {5};
static const char second_name[] = "second unit";

int second_sum(int n) {
    int s = 0;
    for (int i = 0; i < n && i < 32; i++) s += second_table[i];
    return s;
}

__attribute__((noinline)) int second_len(void) {
    return (int)sizeof(second_name) + second_sum(3);
}
