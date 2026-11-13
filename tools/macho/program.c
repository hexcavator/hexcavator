/* A freestanding program for Hexcavator's Mach-O test inputs: code, constant
   and initialized and zeroed data, a thread-local, and globals and
   locals of each kind. With no libSystem, the thread-local bootstrap
   routine dyld would provide is defined here. */

static const char message[] = "hello from rbat";
int counter = 3;
static int hidden_state;
char buffer[4096];
_Thread_local int per_thread = 7;

void tlv_bootstrap(void) __asm__("__tlv_bootstrap");
void tlv_bootstrap(void) {}

static int helper(int x) { return x * 3 + hidden_state; }

__attribute__((noinline)) int compute(int n) {
    int total = 0;
    for (int i = 0; i < n; i++) total += helper(i) + message[i % 15];
    return total;
}

int second_len(void);

int start(void) __asm__("_start");
int start(void) {
    buffer[0] = (char)compute(counter);
    hidden_state = per_thread + second_len();
    return hidden_state;
}
