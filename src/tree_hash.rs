extern crate crypto;

use std::fs::File;
use std::io::Read;
use std::error::Error;

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
 **********************************************************************/
// level # and byte array (the bottom of the tree is level 0 and counts toward the top)
struct TreeHashStackFrame {
  level: u64,
  bytes: Vec<u8>
}

/* collapse_stack makes sure the you'll need at most [ceil(log2(file_size_in_mb)) + 1]
 * levels to compute the tree hash of the total file.  
 *
 * while the stack has multiple frames, pop 2 frames and attempt to combine them.
 * if the 2 frames are not combined, stop iterating.
 *
 * 2 frames are combined when they're at the same level or the 'force' flag is true
 */
fn collapse_stack(stack: &mut Vec<TreeHashStackFrame>, force: bool) {
  loop {
    if stack.len() < 2 {
      return;
    }

    // short-circuit guarantees at least length 2, so unwrap() is ok
    let right = stack.pop().unwrap();
    let left = stack.pop().unwrap();

    if left.level == right.level || force {
      let rolled_up = rollup(&left.bytes, &right.bytes);

      stack.push(TreeHashStackFrame {
        level: left.level + 1,
        bytes: rolled_up
      });
    }
    else {
      stack.push(left);
      stack.push(right);
      return;
    }
  }
}

pub fn tree_hash(filename: &str) -> Result<Vec<u8>, Box<Error>> {
  let mut file = try!(File::open(filename));
  let mut buf: [u8; ONE_MB] = [0; ONE_MB];

  // 32 should handle pretty large (several gb) files without reallocating
  let mut stack: Vec<TreeHashStackFrame> = Vec::with_capacity(32);

  loop {
    let bytes_read = file.read(&mut buf).unwrap();
    if bytes_read == 0 {
      break;
    }

    // read a <=1MB chunk, compute the sha256, and push onto the stack
    let data_slice = &buf[0..bytes_read];

    stack.push(TreeHashStackFrame {
      level: 0,
      bytes: run_sha256(&data_slice)
    });

    // then optimize the stack (collapse like-levels into a higher level)
    collapse_stack(&mut stack, false);
  }

  // force-combine the last bits (eg: promote frames that don't have a pair at their own level)
  collapse_stack(&mut stack, true);

  // the last frame contains the entire file's hash
  match stack.pop() {
    Some(final_frame) => Ok(final_frame.bytes),
    None => panic!("Something went horribly wrong")
  }
}
