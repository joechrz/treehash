
/**********************************************************************
 * Some Helper Functions
 **********************************************************************/
pub fn rollup(lbytes: &Vec<u8>, rbytes: &Vec<u8>) -> Vec<u8> {
    let mut merge_buf: [u8; 64] = [0; 64];

    for i in 0..32 {
        merge_buf[i] = lbytes[i];
        merge_buf[32 + i] = rbytes[i];
    }

    run_sha256(&merge_buf)
}

pub fn run_sha256(bytes: &[u8]) -> Vec<u8> {
    let mut digest = Sha256::new();
    let mut outbuf: [u8; 32] = [0; 32];

    digest.input(bytes);
    digest.result(&mut outbuf);

    outbuf.iter().map(|b| *b).collect()
}

pub fn to_hex_string(bytes: &Vec<u8>) {
    let hex_str = String::with_capacity(64);

    let bytestring = bytes.iter()
        .map(|b| format!("{:02x}", b))
        .fold(hex_str, |mut str_agg, item| { str_agg.push_str(&item); str_agg });

    println!("{}", bytestring);
}

