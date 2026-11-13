/* A user of relr.c's versioned shared object (see build.cmd): its
   references to table (VERS_1) and far (VERS_2) need those versions. */
extern int *table[];
extern int *far;
int **use(void) { return far ? &table[1] : 0; }
