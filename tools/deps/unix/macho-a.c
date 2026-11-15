/* liba: libb by @rpath (its own: @loader_path), and re-exports libre. */
int b_fn(int);
int a_fn(int x) { return b_fn(x); }
#ifdef OLD
int gone_fn(void) { return 0; }
#endif
