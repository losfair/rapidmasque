//! BoringSSL CPU-feature detection for OpenBSD/arm64.
//!
//! The BoringSSL vendored by boring-sys 4 has `OPENSSL_cpuid_setup` for
//! aarch64 on Linux, Apple, FreeBSD, Fuchsia and Windows, but not OpenBSD, so
//! the link fails there. This supplies it the way newer upstream BoringSSL
//! does: read `ID_AA64ISAR0_EL1` via the `machdep.id_aa64isar0` sysctl
//! (OpenBSD 7.1+) and record AES/PMULL/SHA support, so hardware crypto is used
//! where present and boards without the crypto extensions (e.g. Raspberry Pi
//! 4) stay on the NEON code paths.

use std::ffi::c_void;

/// `CTL_MACHDEP` / `CPU_ID_AA64ISAR0` from OpenBSD's <sys/sysctl.h> and
/// <machine/cpu.h>.
const CTL_MACHDEP: libc::c_int = 7;
const CPU_ID_AA64ISAR0: libc::c_int = 2;

/// `OPENSSL_armcap_P` bits from BoringSSL's <openssl/arm_arch.h>.
const ARMV7_NEON: u32 = 1 << 0;
const ARMV8_AES: u32 = 1 << 2;
const ARMV8_SHA1: u32 = 1 << 3;
const ARMV8_SHA256: u32 = 1 << 4;
const ARMV8_PMULL: u32 = 1 << 5;
const ARMV8_SHA512: u32 = 1 << 6;

unsafe extern "C" {
    /// Exported accessor for BoringSSL's (hidden) `OPENSSL_armcap_P`.
    fn OPENSSL_get_armcap_pointer_for_test() -> *mut u32;
}

/// Capability bits for an `ID_AA64ISAR0_EL1` value.
fn armcap(isar0: u64) -> u32 {
    let field = |shift: u32| (isar0 >> shift) & 0xf;
    let (aes, sha1, sha2) = (field(4), field(8), field(12));
    let mut caps = ARMV7_NEON; // Always present on aarch64.
    if aes >= 1 {
        caps |= ARMV8_AES;
    }
    if aes >= 2 {
        caps |= ARMV8_PMULL;
    }
    if sha1 >= 1 {
        caps |= ARMV8_SHA1;
    }
    if sha2 >= 1 {
        caps |= ARMV8_SHA256;
    }
    if sha2 >= 2 {
        caps |= ARMV8_SHA512;
    }
    caps
}

/// Called once by BoringSSL's library initialisation.
#[unsafe(no_mangle)]
pub extern "C" fn OPENSSL_cpuid_setup() {
    let mib = [CTL_MACHDEP, CPU_ID_AA64ISAR0];
    let mut isar0: u64 = 0;
    let mut len = std::mem::size_of::<u64>();
    let rc = unsafe {
        libc::sysctl(
            mib.as_ptr(),
            mib.len() as libc::c_uint,
            &mut isar0 as *mut u64 as *mut c_void,
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    // On failure, fall back to the baseline (NEON only).
    let caps = if rc == 0 { armcap(isar0) } else { ARMV7_NEON };
    unsafe { *OPENSSL_get_armcap_pointer_for_test() |= caps };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_isar0_fields() {
        assert_eq!(armcap(0), ARMV7_NEON);
        // AES+PMULL (2), SHA1 (1), SHA2 incl. SHA512 (2).
        let all = (2 << 4) | (1 << 8) | (2 << 12);
        assert_eq!(
            armcap(all),
            ARMV7_NEON | ARMV8_AES | ARMV8_PMULL | ARMV8_SHA1 | ARMV8_SHA256 | ARMV8_SHA512
        );
    }
}
