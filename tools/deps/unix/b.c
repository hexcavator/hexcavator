/* libb: neither rpath nor runpath; libinh is found by its loaders' rpath
   (the program's: liba's runpath stops none of it). */
int inh_fn(void);
int b_fn(int x) { return x + inh_fn(); }
