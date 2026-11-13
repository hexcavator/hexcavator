// Hand-written CFI for AArch64: return address signing (A and B keys),
// pairs, vector registers, an expression.
  .text
  .globl rules
  .type rules,%function
rules:
  .cfi_startproc
  paciasp
  .cfi_negate_ra_state
  stp x29, x30, [sp, #-32]!
  .cfi_def_cfa_offset 32
  .cfi_offset w30, -24
  .cfi_offset w29, -32
  mov x29, sp
  .cfi_def_cfa w29, 32
  str d8, [sp, #16]
  .cfi_offset b8, -16
  .cfi_register x19, x20
  .cfi_escape 0x16, 0x15, 0x02, 0x8f, 0x08
  nop
  .cfi_remember_state
  ldp x29, x30, [sp], #32
  .cfi_def_cfa sp, 0
  .cfi_restore w30
  .cfi_restore w29
  autiasp
  .cfi_negate_ra_state
  ret
  .cfi_restore_state
  nop
  ret
  .cfi_endproc

  .globl bkey
  .type bkey,%function
bkey:
  .cfi_startproc
  .cfi_b_key_frame
  pacibsp
  .cfi_negate_ra_state
  str x30, [sp, #-16]!
  .cfi_def_cfa_offset 16
  .cfi_offset w30, -16
  ldr x30, [sp], #16
  .cfi_def_cfa_offset 0
  autibsp
  .cfi_negate_ra_state
  ret
  .cfi_endproc
