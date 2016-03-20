extern crate crypto;

use std::fs::File;
use std::io::Read;
use std::error::Error;
use std::collections::LinkedList;

use self::crypto::sha2::Sha256;
use self::crypto::digest::Digest;

const ONE_MB: usize = 1048576;

// TODO: switch to VecDeque; use indexing operations + mutex to parallelize (each thread inserts @
// a specific position)

/**********************************************************************
 * Some Helper Functions
 **********************************************************************/
fn rollup(lbytes: &Vec<u8>, rbytes: &Vec<u8>) -> Vec<u8> {
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

/**********************************************************************
 * The meat of it
 **********************************************************************/
fn load_file(filename: &str) -> LinkedList<Vec<u8>> {
  let mut file = match File::open(filename) {
    Ok(f) => f,
    Err(msg) => panic!(msg)
  };

  let mut buf: [u8; ONE_MB] = [0; ONE_MB];
  let mut hashes: LinkedList<Vec<u8>> = LinkedList::new();

  // generate the hashes for each 1mb chunk and store
  loop {
    let bytes_read = file.read(&mut buf).unwrap();

    if bytes_read == 0 {
      break;
    }

    // TODO: parallelize the hashing
    let data_slice = &buf[0..bytes_read];
    let hash = run_sha256(&data_slice);
    hashes.push_back(hash);
  }

  hashes
}

fn reduce_level(hashes: &mut LinkedList<Vec<u8>>) -> LinkedList<Vec<u8>> {
  let mut combined: LinkedList<Vec<u8>> = LinkedList::new();

  loop {
    let combination = match (hashes.pop_front(), hashes.pop_front()) {
      (Some(left), Some(right)) => {
        rollup(&left, &right)
      },
      (Some(left), None) => left,
      (None, _) => break
    };

    combined.push_back(combination);
  }

  combined
}

pub fn tree_hash(filename: &str) -> Result<Vec<u8>, Box<Error>> {
  let mut hashes = load_file(filename);

  if hashes.is_empty() {
    return Ok(run_sha256(&[]));
  }

  // reduce down to a single hash
  loop {
    let reduction = reduce_level(&mut hashes);
    hashes = reduction;

    if hashes.len() < 2 {
      break;
    }
  }

  match hashes.pop_front() {
    Some(hash) => Ok(hash),
    None => panic!("Error computing hash")
  }
}
