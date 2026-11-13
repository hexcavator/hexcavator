//! Tests of the decoded representation (operands, sizes, decorations, and
//! control flow), independent of text formatting.

use hexcavator_x86::{
    Encoding, Flow, MemSize, Mnemonic, Mode, Operand, RegClass, Register, Rounding, decode, prefix,
};

fn dec(bytes: &[u8]) -> hexcavator_x86::Instruction {
    decode(bytes, Mode::Bits64, 0x1000).unwrap()
}

fn reg(class: RegClass, index: u8) -> Operand {
    Operand::Reg(Register::new(class, index))
}

#[test]
fn memory_operand_fields() {
    // mov rax, qword ptr fs:[rcx+rdx*8-10h]
    let i = dec(&[0x64, 0x48, 0x8B, 0x44, 0xD1, 0xF0]);
    assert_eq!(i.mnemonic(), Mnemonic::Mov);
    assert_eq!(i.len(), 6);
    assert_eq!(i.operands()[0], reg(RegClass::Gpr64, 0));
    let Operand::Mem(m) = i.operands()[1] else {
        panic!()
    };
    assert_eq!(m.segment, Some(Register::new(RegClass::Segment, 4)));
    assert_eq!(m.base, Some(Register::new(RegClass::Gpr64, 1)));
    assert_eq!(m.index, Some(Register::new(RegClass::Gpr64, 2)));
    assert_eq!((m.scale, m.disp, m.disp_size), (8, -0x10, 1));
    assert_eq!(m.size, MemSize::Qword);
    assert_eq!(m.address_size, 8);
}

#[test]
fn rip_relative() {
    // lea rcx, [rip+0x100]
    let i = dec(&[0x48, 0x8D, 0x0D, 0x00, 0x01, 0x00, 0x00]);
    let Operand::Mem(m) = i.operands()[1] else {
        panic!()
    };
    assert!(m.is_rip_relative());
    assert_eq!(m.disp, 0x100);
    assert_eq!(i.next_address().wrapping_add(m.disp as u64), 0x1107);
    assert_eq!(m.size, MemSize::None);
}

#[test]
fn immediates_are_extended_to_operand_size() {
    // add rsp, -8 (imm8 sign-extended to 64 bits)
    let i = dec(&[0x48, 0x83, 0xC4, 0xF8]);
    let Operand::Imm(imm) = i.operands()[1] else {
        panic!()
    };
    assert_eq!((imm.value, imm.size), (0xFFFF_FFFF_FFFF_FFF8, 8));
    // mov eax, imm32
    let i = dec(&[0xB8, 0x78, 0x56, 0x34, 0x12]);
    assert_eq!(
        i.operands()[1],
        Operand::Imm(hexcavator_x86::Immediate {
            value: 0x1234_5678,
            size: 4
        })
    );
    // mov rax, imm64
    let i = dec(&[0x48, 0xB8, 1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(i.len(), 10);
    assert_eq!(
        i.operands()[1],
        Operand::Imm(hexcavator_x86::Immediate {
            value: 0x0807_0605_0403_0201,
            size: 8
        })
    );
}

#[test]
fn branches_and_flow() {
    let jcc = dec(&[0x74, 0x10]);
    assert_eq!(jcc.flow(), Flow::ConditionalJump);
    assert_eq!(jcc.branch_target(), Some(0x1012));
    let jmp = dec(&[0xE9, 0xFB, 0xFF, 0xFF, 0xFF]);
    assert_eq!(jmp.flow(), Flow::Jump);
    assert_eq!(jmp.branch_target(), Some(0x1000));
    let call = dec(&[0xE8, 0, 0, 0, 0]);
    assert_eq!(call.flow(), Flow::Call);
    assert_eq!(call.branch_target(), Some(0x1005));
    assert_eq!(dec(&[0xFF, 0xE0]).flow(), Flow::Jump);
    assert_eq!(dec(&[0xFF, 0xE0]).branch_target(), None);
    assert_eq!(dec(&[0xC3]).flow(), Flow::Return);
    assert_eq!(dec(&[0xCC]).flow(), Flow::Interrupt);
    assert_eq!(dec(&[0x0F, 0x0B]).flow(), Flow::Stop);
    assert_eq!(dec(&[0x90]).flow(), Flow::Next);
}

#[test]
fn byte_registers_depend_on_rex() {
    assert_eq!(dec(&[0x88, 0xE0]).operands()[1], reg(RegClass::Gpr8High, 0)); // ah
    assert_eq!(
        dec(&[0x40, 0x88, 0xE0]).operands()[1],
        reg(RegClass::Gpr8, 4)
    ); // spl
    assert_eq!(
        dec(&[0x45, 0x88, 0xC8]).operands()[0],
        reg(RegClass::Gpr8, 8)
    ); // r8b
}

#[test]
fn prefixes() {
    let i = dec(&[0xF0, 0x48, 0x0F, 0xB1, 0x0A]); // lock cmpxchg [rdx], rcx
    assert_ne!(i.prefixes() & prefix::LOCK, 0);
    let i = dec(&[0xF3, 0x48, 0xA5]); // rep movsq
    assert_ne!(i.prefixes() & prefix::REP, 0);
    assert!(i.is_string());
}

#[test]
fn vex_and_evex() {
    // vaddps ymm1, ymm2, ymm3
    let i = dec(&[0xC5, 0xEC, 0x58, 0xCB]);
    assert_eq!(i.encoding(), Encoding::Vex);
    assert_eq!(i.vector_length(), 32);
    assert_eq!(
        i.operands(),
        &[
            reg(RegClass::Ymm, 1),
            reg(RegClass::Ymm, 2),
            reg(RegClass::Ymm, 3)
        ]
    );

    // vaddps zmm0{k3}{z}, zmm0, zmm1
    let i = dec(&[0x62, 0xF1, 0x7C, 0xCB, 0x58, 0xC1]);
    assert_eq!(i.encoding(), Encoding::Evex);
    assert_eq!(
        (i.mask(), i.zeroing(), i.vector_length()),
        (Some(3), true, 64)
    );

    // vaddps zmm0, zmm0, zmm1, {rd-sae}
    let i = dec(&[0x62, 0xF1, 0x7C, 0x38, 0x58, 0xC1]);
    assert_eq!(i.rounding(), Some(Rounding::Down));

    // vpaddd zmm0, zmm0, dword bcst [rax+4]: disp8*N with broadcast is N=4.
    let i = dec(&[0x62, 0xF1, 0x7D, 0x58, 0xFE, 0x40, 0x01]);
    let Operand::Mem(m) = i.operands()[2] else {
        panic!()
    };
    assert_eq!((m.disp, m.size, m.broadcast), (4, MemSize::Dword, 16));

    // vmovups zmm0, [rsp+0x40]: disp8*N without broadcast is N=64.
    let i = dec(&[0x62, 0xF1, 0x7C, 0x48, 0x10, 0x44, 0x24, 0x01]);
    let Operand::Mem(m) = i.operands()[1] else {
        panic!()
    };
    assert_eq!((m.disp, m.size), (0x40, MemSize::Zmmword));

    // vgatherdps zmm0{k1}, [rax+zmm1*4]
    let i = dec(&[0x62, 0xF2, 0x7D, 0x49, 0x92, 0x04, 0x88]);
    let Operand::Mem(m) = i.operands()[1] else {
        panic!()
    };
    assert_eq!(m.index, Some(Register::new(RegClass::Zmm, 1)));
    assert_eq!(m.scale, 4);
}

#[test]
fn invalid_and_truncated() {
    assert_eq!(
        decode(&[0x0F, 0xFF], Mode::Bits64, 0),
        Err(hexcavator_x86::DecodeError::Invalid)
    );
    assert_eq!(
        decode(&[0x48, 0x8B], Mode::Bits64, 0),
        Err(hexcavator_x86::DecodeError::Truncated)
    );
    assert_eq!(
        decode(&[], Mode::Bits64, 0),
        Err(hexcavator_x86::DecodeError::Truncated)
    );
    // 15 bytes of prefixes cannot form an instruction.
    assert!(decode(&[0x66; 16], Mode::Bits64, 0).is_err());
    // Arbitrary inputs never panic.
    let mut state = 0x1234_5678_9ABC_DEF0u64;
    for _ in 0..200_000 {
        let mut bytes = [0u8; 15];
        for b in &mut bytes {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *b = state.to_le_bytes()[0];
        }
        for mode in [Mode::Bits16, Mode::Bits32, Mode::Bits64] {
            if let Ok(i) = decode(&bytes, mode, 0) {
                assert!(i.len() <= 15);
                let _ = hexcavator_x86::format::to_string(&i);
            }
        }
    }
}

#[test]
fn register_aliasing() {
    let al = Register::gpr(1, 0, false);
    let ah = Register::gpr(1, 4, false);
    let eax = Register::gpr(4, 0, false);
    assert_eq!(al.full(), eax.full());
    assert_eq!(ah.full(), eax.full());
    assert_eq!(Register::vector(16, 5).full(), Register::vector(64, 5));
}

#[test]
fn sixteen_bit_mode() {
    // mov ax, [bx+si+4]
    let i = decode(&[0x8B, 0x40, 0x04], Mode::Bits16, 0).unwrap();
    assert_eq!(i.operands()[0], reg(RegClass::Gpr16, 0));
    let Operand::Mem(m) = i.operands()[1] else {
        panic!()
    };
    assert_eq!(m.base, Some(Register::new(RegClass::Gpr16, 3)));
    assert_eq!(m.index, Some(Register::new(RegClass::Gpr16, 6)));
    assert_eq!(m.address_size, 2);
    // 66 selects a 32-bit operand in 16-bit mode.
    let i = decode(&[0x66, 0xB8, 1, 0, 0, 0], Mode::Bits16, 0).unwrap();
    assert_eq!(i.operands()[0], reg(RegClass::Gpr32, 0));
}
