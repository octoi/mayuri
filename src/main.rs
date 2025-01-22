use std::env;
use std::path::Path;

use mayuri::{decrypt_path, encrypt_path};

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 4 {
        print_usage();
        std::process::exit(0);
    }

    let option = &args[1].to_string();

    let file_path = Path::new(&args[2]);
    let password = &args[3];

    match option.as_str() {
        "-d" => {
            println!("Decrypting file..");
            match decrypt_path(file_path, password) {
                Ok(_) => {
                    println!("Decrypted file");
                }
                Err(err) => {
                    println!("{:?}", err);
                }
            };
        }
        "-e" => {
            println!("Encrypting file..");
            match encrypt_path(file_path, password) {
                Ok(_) => {
                    println!("Encrypted file");
                }
                Err(err) => {
                    println!("{:?}", err);
                }
            };
        }
        _ => {
            print_usage();
            std::process::exit(0);
        }
    }
}

fn print_usage() {
    println!("USAGE: MAYURI\n");
    println!("mayuri <option> <location> <password>");
    println!("\nOPTIONS");
    println!("-d - Decrypt");
    println!("-e - Encrypt\n");
    println!("eg: mayuri -d ./foldername password");
}
