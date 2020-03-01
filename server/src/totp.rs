use byteorder::{BigEndian, ByteOrder};
use std::time::SystemTime;

// Unfortunately libsodium doesn't give us HMAC-SHA1, so link to openssl for it
mod crypto {
    use libc::c_void;

    const EVP_MAX_MD_SIZE: usize = 64;

    #[link(name = "crypto")]
    extern "C" {
        fn EVP_sha1() -> *const c_void;
        fn HMAC(
            evp_md: *const c_void,
            key: *const u8,
            key_len: i32,
            d: *const u8,
            n: i32,
            md: *mut u8,
            md_len: *mut u32,
        ) -> *mut u8;
    }

    pub fn hmac_sha1(key: &[u8], message: &[u8]) -> Vec<u8> {
        let mut digest = vec![0; EVP_MAX_MD_SIZE];
        let mut digest_len = digest.len() as u32;

        unsafe {
            HMAC(
                EVP_sha1(),
                key.as_ptr(),
                key.len() as i32,
                message.as_ptr(),
                message.len() as i32,
                digest.as_mut_ptr(),
                &mut digest_len,
            );
        }

        digest.resize(digest_len as usize, 0);
        digest
    }
}

pub const TOTP_LEN: usize = 6;

pub fn calc_totp(key: &[u8], time: SystemTime) -> String {
    let timecode = time.duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs() / 30;
    let mut message = [0; 8];
    BigEndian::write_u64(&mut message, timecode);

    let digest = crypto::hmac_sha1(key.as_ref(), message.as_ref());

    let offset = (digest[digest.len() - 1] & 0xf) as usize;
    let code = u32::from(digest[offset]) << 24 | u32::from(digest[offset + 1]) << 16
        | u32::from(digest[offset + 2]) << 8 | u32::from(digest[offset + 3]);
    let code = code & 0x7FFF_FFFF;
    format!("{:06}", code % 1_000_000)
}
