extern crate docopt;
extern crate rustc_serialize;

use std::env;
use std::io;
use std::io::Write;
use docopt::Docopt;

mod tree_hash;

const USAGE: &'static str = "
treehash 

calculates the sha256 tree-hash according to the algorithm laid out at
http://docs.aws.amazon.com/amazonglacier/latest/dev/checksum-calculations.html

if no filename is specified, reads from <stdin>

Usage: treehash [options] [<filename>]
       treehash --help

Options:
  -b, --binary      Output the result in binary form (default: hex string)
";

#[derive(RustcDecodable)]
struct Args {
    arg_filename: String,
    flag_binary: bool
}

fn main() {
    let args: Args = Docopt::new(USAGE)
        .and_then(|d| d.argv(env::args()).decode())
        .unwrap_or_else(|e| e.exit());

    match tree_hash::tree_hash(&args.arg_filename) {
        Ok(hash_bytes) => {
            if args.flag_binary {
                match io::stdout().write(&hash_bytes) {
                    Ok(_) => (),
                    Err(_) => panic!("Error printing hash bytes")
                };
            }
            else {
                tree_hash::to_hex_string(&hash_bytes);
            }
        },
        Err(_) => println!("Error calculating tree hash")
    }
}
