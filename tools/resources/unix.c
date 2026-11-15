/* What an ELF image says of itself, for `hexc resources`: an ABI tag note
   (as a C library's start files give one), with the linker's build ID and
   package metadata (build.cmd). */
__asm__(".section .note.ABI-tag,\"a\",@note\n"
        ".balign 4\n"
        ".long 4, 16, 1\n"
        ".asciz \"GNU\"\n"
        ".long 0, 3, 2, 0\n"
        ".text\n");

void _start(void) {
    for (;;) {
    }
}
