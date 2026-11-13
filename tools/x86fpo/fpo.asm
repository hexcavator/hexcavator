; SPDX-License-Identifier: Apache-2.0
;
; A hand-written function described by an old-style FPO record (MASM's
; .FPO directive), for frames.c: asm_fpo(f) calls f.

.686
.model flat, C
.code

asm_fpo PROC
    ; cdwLocals, cdwParams, cbProlog, cbRegs, fUseBP, cbFrame (FRAME_FPO).
    ; (The record starts here, where the directive is.)
    .FPO (2, 1, 5, 2, 0, 0)
    push    ebx
    push    esi
    sub     esp, 8
    mov     eax, [esp + 20]
    call    eax
    add     esp, 8
    pop     esi
    pop     ebx
    ret
asm_fpo ENDP

END
