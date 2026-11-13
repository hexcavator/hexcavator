# Hand-written CFI using every rule kind (x86-64).
  .text
  .globl rules
  .type rules,@function
rules:
  .cfi_startproc
  .cfi_personality 0x9b, DW.ref.__gcc_personality_v0
  .cfi_lsda 0x1b, .Llsda
  pushq %rbp
  .cfi_adjust_cfa_offset 8
  .cfi_rel_offset %rbp, 0
  .cfi_remember_state
  movq %rsp, %rbp
  .cfi_def_cfa_register %rbp
  .cfi_register %rbx, %r12
  .cfi_undefined %r13
  .cfi_same_value %r14
  .cfi_val_offset %r15, -24
  # DW_CFA_expression rbx, [DW_OP_breg6 +16]
  .cfi_escape 0x10, 0x03, 0x02, 0x76, 0x10
  # DW_CFA_val_expression r12, DW_OP_breg6 +8, DW_OP_deref
  .cfi_escape 0x16, 0x0c, 0x03, 0x76, 0x08, 0x06
  nop
  # DW_CFA_def_cfa_expression DW_OP_breg7 +8, DW_OP_deref
  .cfi_escape 0x0f, 0x03, 0x77, 0x08, 0x06
  nop
  # DW_CFA_expression rsi: lit8, breg7 0, plus, constu 300, minus, const1s -3, plus
  .cfi_escape 0x10, 0x04, 0x0b, 0x38, 0x77, 0x00, 0x22, 0x10, 0xac, 0x02, 0x1c, 0x09, 0xfd, 0x22
  nop
  .cfi_restore_state
  .cfi_restore %rbp
  .cfi_return_column %rbp
  ret
  .cfi_endproc

  .globl signal
  .type signal,@function
signal:
  .cfi_startproc simple
  .cfi_signal_frame
  .cfi_def_cfa %rsp, 160
  .cfi_offset %rip, -8
  .cfi_escape 0x2e, 0x10
  nop
  .cfi_def_cfa_offset 200
  .cfi_offset %rbx, -160
  .cfi_offset %r8, -152
  nop
  ret
  .cfi_endproc

  .section .rodata
.Llsda:
  .byte 0xff, 0xff, 0x01, 0x00
  .hidden DW.ref.__gcc_personality_v0
  .weak DW.ref.__gcc_personality_v0
  .section .data.DW.ref.__gcc_personality_v0,"awG",@progbits,DW.ref.__gcc_personality_v0,comdat
DW.ref.__gcc_personality_v0:
  .quad __gcc_personality_v0
