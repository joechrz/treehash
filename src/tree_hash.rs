extern crate crypto;

use std::fs::File;
use std::io::Read;
use std::error::Error;
use std::collections::LinkedList;

use self::crypto::sha2::Sha256;
use self::crypto::digest::Digest;

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

fn hash_reduce(hashes: &mut LinkedList<Vec<u8>>) -> Vec<u8> {
  let mut cur: LinkedList<Vec<u8>> = LinkedList::new();
  let mut next: LinkedList<Vec<u8>> = LinkedList::new();
  let mut merge_buf: [u8; 64] = [0; 64];

  // TODO: figure out how to coerce the types to be the same
  for h in hashes {
    cur.push_back(h.iter().cloned().collect());
  }

  loop {
    let mut merged_pairs = 0;

    loop {
      match (cur.pop_front(), cur.pop_front()) {
        (Some(left), Some(right)) => {
          for i in 0..32 {
            merge_buf[i] = left[i];
            merge_buf[32 + i] = right[i];
          }

          next.push_back(run_sha256(&merge_buf));
          merged_pairs += 1;
        },

        (Some(left), None) => next.push_back(left),
        (None, None) => break,
        (None, _) => ()
      }
    }

    if merged_pairs == 0 {
      match next.pop_front() {
        Some(hash) => return hash,
        None => panic!("No hashes!")
      };
    }
    else {
      cur = next;
      next = LinkedList::new();
    }
  }
}

pub fn tree_hash(filename: &str) -> Result<Vec<u8>, Box<Error>> {
  const ONE_MB: usize = 1048576;

  let mut f = try!(File::open(filename));
  let mut buf: [u8; ONE_MB] = [0; ONE_MB];
  let mut hashes = LinkedList::<Vec<u8>>::new();

  loop {
    let bytes_read = try!(f.read(&mut buf));
    if bytes_read == 0 {
      break;
    }

    let sha = run_sha256(&buf[0..bytes_read]);
    hashes.push_back(sha);
  }

  let final_hash = hash_reduce(&mut hashes);

  Ok(final_hash)
}
