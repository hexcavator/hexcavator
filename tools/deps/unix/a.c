/* liba: by runpath, libb; by ld.so.conf, libopt; and a symbol nothing
   defines. */
int b_fn(int);
int opt_fn(void);
int nowhere(void);
int a_fn(int x) { return b_fn(x) + opt_fn() + nowhere(); }
