use smallvec::SmallVec;
use std::fmt;

/// Trace 日志格式
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum TraceFormat {
    Unidbg,
    Gumtrace,
    Qbdi,
}

impl Default for TraceFormat {
    fn default() -> Self {
        TraceFormat::Unidbg
    }
}

/// ARM64 寄存器标识符。
///
/// 使用 `u8` 编码：x0-x28=0-28, x29(fp)=29, x30(lr)=30, sp=31, xzr=32,
/// v0_lo-v31_lo=33-64, nzcv=65, v0_hi-v31_hi=66-97。总共 98 个寄存器。
#[derive(Copy, Clone, Eq, PartialEq, Hash, serde::Serialize, serde::Deserialize)]
pub struct RegId(pub u8);

#[allow(dead_code)]
impl RegId {
    pub const X0: Self = Self(0);
    pub const X1: Self = Self(1);
    pub const X2: Self = Self(2);
    pub const X3: Self = Self(3);
    pub const X4: Self = Self(4);
    pub const X5: Self = Self(5);
    pub const X6: Self = Self(6);
    pub const X7: Self = Self(7);
    pub const X8: Self = Self(8);
    pub const X9: Self = Self(9);
    pub const X10: Self = Self(10);
    pub const X11: Self = Self(11);
    pub const X12: Self = Self(12);
    pub const X13: Self = Self(13);
    pub const X14: Self = Self(14);
    pub const X15: Self = Self(15);
    pub const X16: Self = Self(16);
    pub const X17: Self = Self(17);
    pub const X18: Self = Self(18);
    pub const X19: Self = Self(19);
    pub const X20: Self = Self(20);
    pub const X21: Self = Self(21);
    pub const X22: Self = Self(22);
    pub const X23: Self = Self(23);
    pub const X24: Self = Self(24);
    pub const X25: Self = Self(25);
    pub const X26: Self = Self(26);
    pub const X27: Self = Self(27);
    pub const X28: Self = Self(28);
    pub const X29: Self = Self(29);
    pub const X30: Self = Self(30);
    pub const SP: Self = Self(31);
    pub const XZR: Self = Self(32);
    pub const V0: Self = Self(33);
    pub const V1: Self = Self(34);
    pub const V2: Self = Self(35);
    pub const V3: Self = Self(36);
    pub const V4: Self = Self(37);
    pub const V5: Self = Self(38);
    pub const V6: Self = Self(39);
    pub const V7: Self = Self(40);
    pub const V8: Self = Self(41);
    pub const V9: Self = Self(42);
    pub const V10: Self = Self(43);
    pub const V11: Self = Self(44);
    pub const V12: Self = Self(45);
    pub const V13: Self = Self(46);
    pub const V14: Self = Self(47);
    pub const V15: Self = Self(48);
    pub const V16: Self = Self(49);
    pub const V17: Self = Self(50);
    pub const V18: Self = Self(51);
    pub const V19: Self = Self(52);
    pub const V20: Self = Self(53);
    pub const V21: Self = Self(54);
    pub const V22: Self = Self(55);
    pub const V23: Self = Self(56);
    pub const V24: Self = Self(57);
    pub const V25: Self = Self(58);
    pub const V26: Self = Self(59);
    pub const V27: Self = Self(60);
    pub const V28: Self = Self(61);
    pub const V29: Self = Self(62);
    pub const V30: Self = Self(63);
    pub const V31: Self = Self(64);
    pub const NZCV: Self = Self(65);
    // SIMD hi-lanes (high 64-bit of v0-v31)
    pub const V0_HI: Self = Self(66);
    pub const V1_HI: Self = Self(67);
    pub const V2_HI: Self = Self(68);
    pub const V3_HI: Self = Self(69);
    pub const V4_HI: Self = Self(70);
    pub const V5_HI: Self = Self(71);
    pub const V6_HI: Self = Self(72);
    pub const V7_HI: Self = Self(73);
    pub const V8_HI: Self = Self(74);
    pub const V9_HI: Self = Self(75);
    pub const V10_HI: Self = Self(76);
    pub const V11_HI: Self = Self(77);
    pub const V12_HI: Self = Self(78);
    pub const V13_HI: Self = Self(79);
    pub const V14_HI: Self = Self(80);
    pub const V15_HI: Self = Self(81);
    pub const V16_HI: Self = Self(82);
    pub const V17_HI: Self = Self(83);
    pub const V18_HI: Self = Self(84);
    pub const V19_HI: Self = Self(85);
    pub const V20_HI: Self = Self(86);
    pub const V21_HI: Self = Self(87);
    pub const V22_HI: Self = Self(88);
    pub const V23_HI: Self = Self(89);
    pub const V24_HI: Self = Self(90);
    pub const V25_HI: Self = Self(91);
    pub const V26_HI: Self = Self(92);
    pub const V27_HI: Self = Self(93);
    pub const V28_HI: Self = Self(94);
    pub const V29_HI: Self = Self(95);
    pub const V30_HI: Self = Self(96);
    pub const V31_HI: Self = Self(97);
    /// Total number of distinct RegId values (0..=97).
    pub const COUNT: usize = 98;

    pub fn is_zero(self) -> bool {
        self == Self::XZR
    }

    /// For a SIMD lo-lane RegId (33..=64), return the corresponding hi-lane.
    pub fn simd_hi(self) -> Option<RegId> {
        if self.0 >= 33 && self.0 <= 64 {
            Some(RegId(self.0 + 33))
        } else {
            None
        }
    }

    /// True if this is a SIMD lo-lane (v0..v31, IDs 33-64).
    pub fn is_simd_lo(self) -> bool { self.0 >= 33 && self.0 <= 64 }

    /// True if this is a SIMD hi-lane (v0_hi..v31_hi, IDs 66-97).
    pub fn is_simd_hi(self) -> bool { self.0 >= 66 && self.0 <= 97 }

    /// True if this is any SIMD register (lo or hi lane).
    pub fn is_simd(self) -> bool { self.is_simd_lo() || self.is_simd_hi() }
}

impl fmt::Debug for RegId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::SP => write!(f, "sp"),
            Self::XZR => write!(f, "xzr"),
            Self::NZCV => write!(f, "nzcv"),
            r if r.0 <= 30 => write!(f, "x{}", r.0),
            r if (33..=64).contains(&r.0) => write!(f, "v{}", r.0 - 33),
            r if (66..=97).contains(&r.0) => write!(f, "v{}_hi", r.0 - 66),
            _ => write!(f, "reg({})", self.0),
        }
    }
}

/// Parse trace register name to RegId, auto-normalizing (w->x, b/h/s/d/q->v).
///
/// Hot path: called 6-10 times per trace line. Uses hand-written 1-2 digit
/// parsing instead of `str::parse::<u8>()` for speed.
pub fn parse_reg(name: &str) -> Option<RegId> {
    let bytes = name.as_bytes();
    let len = bytes.len();
    if len < 2 {
        return None;
    }

    // Fast path for special registers (2-4 chars)
    match len {
        2 => {
            if bytes == b"sp" {
                return Some(RegId::SP);
            }
            if bytes == b"fp" {
                return Some(RegId::X29);
            }
            if bytes == b"lr" {
                return Some(RegId::X30);
            }
        }
        3 => match (bytes[0], bytes[1], bytes[2]) {
            (b'x', b'z', b'r') | (b'w', b'z', b'r') => return Some(RegId::XZR),
            (b'w', b's', b'p') => return Some(RegId::SP),
            _ => {}
        },
        4 => {
            if bytes == b"nzcv" {
                return Some(RegId::NZCV);
            }
        }
        _ => {}
    }

    // General register: prefix + 1-2 digit number
    let prefix = bytes[0];
    let num = match len {
        2 => {
            let d = bytes[1].wrapping_sub(b'0');
            if d > 9 {
                return None;
            }
            d
        }
        3 => {
            let d1 = bytes[1].wrapping_sub(b'0');
            let d2 = bytes[2].wrapping_sub(b'0');
            if d1 > 9 || d2 > 9 {
                return None;
            }
            d1 * 10 + d2
        }
        _ => return None,
    };

    match prefix {
        b'x' if num <= 30 => Some(RegId(num)),
        b'w' if num <= 30 => Some(RegId(num)), // w->x normalization
        b'v' if num <= 31 => Some(RegId(33 + num)),
        b'q' if num <= 31 => Some(RegId(33 + num)), // q->v normalization
        b'd' if num <= 31 => Some(RegId(33 + num)), // d->v normalization
        b's' if num <= 31 => Some(RegId(33 + num)), // s->v normalization
        b'b' if num <= 31 => Some(RegId(33 + num)), // b->v normalization
        b'h' if num <= 31 => Some(RegId(33 + num)), // h->v normalization
        _ => None,
    }
}

/// 指令操作数。
///
/// 从反汇编文本中提取的操作数，仅保留对依赖分析有用的信息。
/// 不包含内存引用（由 [`MemOp`] 单独表示）和条件码（由 [`InsnClass`](crate::insn_class::InsnClass) 隐含）。
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum Operand {
    /// 普通寄存器操作数（x0-x28, sp, v0-v31, nzcv 等）。
    Reg(RegId),
    /// 带 lane 索引的 SIMD 寄存器操作数（如 `v0.s[1]`）。
    RegLane(RegId, u8),
    /// 立即数操作数（#imm，含移位量）。
    Imm(i64),
}

impl Operand {
    pub fn as_reg(&self) -> Option<RegId> {
        match self {
            Operand::Reg(r) => Some(*r),
            Operand::RegLane(r, _) => Some(*r),
            Operand::Imm(_) => None,
        }
    }
}

/// 内存操作信息。
///
/// 从 trace 行中 `; mem[READ/WRITE] abs=0x...` 注解提取。
#[derive(Debug, Clone)]
pub struct MemOp {
    /// 是否为写操作（`true` = WRITE, `false` = READ）。
    pub is_write: bool,
    /// 绝对内存地址。
    pub abs: u64,
    /// 单个元素宽度（字节），由助记符和寄存器前缀推导。
    pub elem_width: u8,
    /// 掩码后的存/取值（用于值相等性剪枝）。
    /// SIMD 128-bit（q 寄存器）为 None。
    pub value: Option<u64>,
    /// Pair 指令（ldp/stp）第二个寄存器的值。
    pub value2: Option<u64>,
    /// 128-bit 第一个寄存器 low 64 位（elem_width == 16 时有效）。
    pub value_lo: Option<u64>,
    /// 128-bit 第一个寄存器 high 64 位（elem_width == 16 时有效）。
    pub value_hi: Option<u64>,
    /// 128-bit pair 第二个寄存器 low 64 位（elem_width == 16 时有效）。
    pub value2_lo: Option<u64>,
    /// 128-bit pair 第二个寄存器 high 64 位（elem_width == 16 时有效）。
    pub value2_hi: Option<u64>,
}

/// ARM64 助记符的栈上存储（最长 ~7 字节）。
/// 零堆分配，支持 &str 比较和 Display。
#[derive(Clone, Copy, Default)]
pub struct Mnemonic {
    buf: [u8; 8],
    len: u8,
}

impl Mnemonic {
    pub fn new(s: &str) -> Self {
        let bytes = s.as_bytes();
        let len = bytes.len().min(8);
        let mut buf = [0u8; 8];
        buf[..len].copy_from_slice(&bytes[..len]);
        Self {
            buf,
            len: len as u8,
        }
    }

    pub fn as_str(&self) -> &str {
        // SAFETY: buf is always populated from &str in new(), so it's valid UTF-8
        unsafe { std::str::from_utf8_unchecked(&self.buf[..self.len as usize]) }
    }
}

impl PartialEq<&str> for Mnemonic {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

impl std::fmt::Debug for Mnemonic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "\"{}\"", self.as_str())
    }
}

impl std::fmt::Display for Mnemonic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// 解析后的 trace 行。
///
/// 每行 trace 被解析为此结构，供分类和 DEF/USE 分析使用。
/// 此结构是临时的——每行创建、使用后即丢弃。
#[derive(Debug, Clone, Default)]
pub struct ParsedLine {
    /// 指令助记符（如 "add", "ldr", "b.eq"）。
    pub mnemonic: Mnemonic,
    /// 操作数列表（寄存器和立即数）。
    pub operands: SmallVec<[Operand; 4]>,
    /// 内存操作信息（仅 load/store 类指令有）。
    pub mem_op: Option<MemOp>,
    /// 是否包含 `=>` 箭头（区分有无输出值的行）。
    pub has_arrow: bool,
    /// `" => "` 在原始行中的绝对字节位置（避免 phase2 重复搜索）。
    pub arrow_pos: Option<usize>,
    /// 基址寄存器（`[Xn, ...]` 中的 Xn）。
    pub base_reg: Option<RegId>,
    /// 是否有回写标记（`!` 或 `], #offset`）。
    pub writeback: bool,
    /// SIMD lane 索引（如 `{v0.s}[1]` 中的 1）。
    pub lane_index: Option<u8>,
    /// SIMD lane 元素宽度（字节），从排列标识符推断：s=4, d=8, h=2, b=1。
    pub lane_elem_width: Option<u8>,
    /// `=>` 箭头左侧的寄存器值对（仅 validate 模式填充）。
    pub pre_arrow_regs: Option<Box<SmallVec<[(RegId, u64); 4]>>>,
    /// `=>` 箭头右侧的寄存器值对（仅 validate 模式填充）。
    pub post_arrow_regs: Option<Box<SmallVec<[(RegId, u64); 4]>>>,
}

/// @LINE 目标验证条目，传入扫描器在 Pass 1 中验证
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum LineTarget {
    Reg(RegId), // 验证该行 DEF 了此寄存器
    Mem(u64),   // 验证该行 STORE 了此地址
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reg_id_constants() {
        assert_ne!(RegId::X0, RegId::X30);
        assert_ne!(RegId::X0, RegId::V0);
        assert_ne!(RegId::SP, RegId::XZR);
        assert_eq!(RegId::NZCV.0, 65);
    }

    #[test]
    fn test_reg_id_is_zero() {
        assert!(RegId::XZR.is_zero());
        assert!(!RegId::X0.is_zero());
        assert!(!RegId::SP.is_zero());
    }

    #[test]
    fn test_parse_reg_x_registers() {
        assert_eq!(parse_reg("x0"), Some(RegId::X0));
        assert_eq!(parse_reg("x30"), Some(RegId::X30));
        assert_eq!(parse_reg("x8"), Some(RegId(8)));
    }

    #[test]
    fn test_parse_reg_w_normalizes_to_x() {
        assert_eq!(parse_reg("w0"), Some(RegId::X0));
        assert_eq!(parse_reg("w8"), Some(RegId(8)));
        assert_eq!(parse_reg("w30"), Some(RegId::X30));
    }

    #[test]
    fn test_parse_reg_simd_normalizes_to_v() {
        assert_eq!(parse_reg("v0"), Some(RegId::V0));
        assert_eq!(parse_reg("q0"), Some(RegId::V0));
        assert_eq!(parse_reg("d0"), Some(RegId::V0));
        assert_eq!(parse_reg("s0"), Some(RegId::V0));
        assert_eq!(parse_reg("b0"), Some(RegId::V0));
        assert_eq!(parse_reg("v31"), Some(RegId::V31));
        assert_eq!(parse_reg("q15"), Some(RegId(33 + 15)));
    }

    #[test]
    fn test_parse_reg_special() {
        assert_eq!(parse_reg("sp"), Some(RegId::SP));
        assert_eq!(parse_reg("wsp"), Some(RegId::SP));
        assert_eq!(parse_reg("xzr"), Some(RegId::XZR));
        assert_eq!(parse_reg("wzr"), Some(RegId::XZR));
        assert_eq!(parse_reg("nzcv"), Some(RegId::NZCV));
    }

    #[test]
    fn test_parse_reg_fp_lr_alias() {
        assert_eq!(parse_reg("fp"), Some(RegId::X29));
        assert_eq!(parse_reg("lr"), Some(RegId::X30));
    }

    #[test]
    fn test_parse_reg_invalid() {
        assert_eq!(parse_reg(""), None);
        assert_eq!(parse_reg("#5"), None);
        assert_eq!(parse_reg("x32"), None);
        assert_eq!(parse_reg("v32"), None);
        assert_eq!(parse_reg("hello"), None);
    }

    #[test]
    fn test_operand_as_reg() {
        let reg_op = Operand::Reg(RegId::X8);
        assert_eq!(reg_op.as_reg(), Some(RegId::X8));

        let imm_op = Operand::Imm(42);
        assert_eq!(imm_op.as_reg(), None);

        let lane_op = Operand::RegLane(RegId::V0, 2);
        assert_eq!(lane_op.as_reg(), Some(RegId::V0));
    }

    #[test]
    fn test_line_target_variants() {
        let t1 = LineTarget::Reg(RegId::X0);
        let t2 = LineTarget::Mem(0xbffff010);
        match t1 {
            LineTarget::Reg(r) => assert_eq!(r, RegId::X0),
            _ => panic!(),
        }
        match t2 {
            LineTarget::Mem(a) => assert_eq!(a, 0xbffff010),
            _ => panic!(),
        }
    }
}
