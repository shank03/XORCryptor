/*
 * Copyright (c) 2022, Shashank Verma <shashank.verma2002@gmail.com>(shank03)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 */

use std::{
    error::Error,
    fs,
    io::{stdin, Write},
    path,
    sync::{self, Arc},
    thread::{self, JoinHandle},
};

use hmac::{Hmac, Mac};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use sha2::Sha256;
use xor_cryptor::XORCryptor;

use cli::CliArgs;
use file_handler::FileHandler;

mod cli;
mod file_handler;

type HmacSha256 = Hmac<Sha256>;

fn main() {
    let config = CliArgs::parse_args();
    if config.is_err() {
        println!("Error: {}", config.err().unwrap());
        return;
    }
    let config = config.unwrap();
    let total_paths = config.get_path_count();
    println!("{} files found.\n", total_paths);

    println!("Enter key: ");
    let mut key = String::new();
    let len = stdin().read_line(&mut key);
    if len.is_err() {
        println!("Error reading key input");
        return;
    }
    let key = key.trim().replace("\n", "").replace("\r", "");
    let xrc = XORCryptor::new(&key);
    if xrc.is_err() {
        println!("Error: {}", xrc.err().unwrap());
        return;
    }
    let xrc = Arc::new(xrc.unwrap());

    let multi_pr = MultiProgress::new();
    let style =
        ProgressStyle::with_template("[{elapsed}] [{bar:30.cyan/yellow}] {pos:>6}/{len:6} {msg}")
            .unwrap()
            .progress_chars("=>-");

    let key = Arc::new(key);
    let mut handles = Vec::<JoinHandle<()>>::new();
    let pool = config.get_paths();

    let mut progress_bars = Vec::<Box<ProgressBar>>::new();
    for i in 0..config.get_jobs() {
        if pool[i].is_empty() {
            break;
        }

        let pb = if i == 0 {
            multi_pr.add(ProgressBar::new(pool[i].len() as u64))
        } else {
            multi_pr.insert_after(
                &progress_bars[i - 1],
                ProgressBar::new(pool[i].len() as u64),
            )
        };
        pb.set_style(style.clone());
        progress_bars.push(Box::new(pb));
    }

    let _ = multi_pr.println(if config.to_encrypt() {
        "\nEncrypting..."
    } else {
        "\nDecrypting..."
    });

    let mut pbr_idx = 0usize;
    for path_list in pool {
        if path_list.is_empty() {
            break;
        }

        let key = key.clone();
        let xrc = xrc.clone();
        let preserve = config.is_preserve();
        let to_encrypt = config.to_encrypt();
        let n_jobs = config.get_jobs();

        let pr_br = progress_bars[pbr_idx].clone();
        handles.push(thread::spawn(move || {
            let list = path_list;
            let pbr = pr_br;
            pbr.set_position(0);

            for path in list {
                pbr.set_message(String::from(path.file_name().unwrap().to_str().unwrap()));
                let res = exec_cli(&path, key.as_ref(), &xrc, preserve, to_encrypt, n_jobs);
                match res {
                    Ok(op_path) => {
                        if op_path.is_some() {
                            let _ = fs::remove_file(op_path.unwrap());
                        }
                    }
                    Err(err) => {
                        pbr.println(format!(
                            "Error: {}: {}",
                            path.file_name().unwrap().to_str().unwrap(),
                            err.to_string()
                        ));
                    }
                }
                pbr.inc(1);
            }
            pbr.finish_with_message("Done");
        }));
        pbr_idx += 1;
    }
    for h in handles {
        h.join().unwrap();
    }
}

fn exec_cli(
    path: &path::PathBuf,
    key: &String,
    xrc: &Arc<XORCryptor>,
    preserve: bool,
    to_encrypt: bool,
    n_jobs: usize,
) -> Result<Option<String>, Box<dyn Error>> {
    let mut dest_path = String::from(path.clone().to_str().unwrap());
    if to_encrypt {
        if dest_path.ends_with(FileHandler::FILE_EXTENSION_STR) {
            println!("Invalid file: {}", dest_path);
            return Ok(Some(dest_path));
        }
        dest_path.push_str(FileHandler::FILE_EXTENSION_STR);
    } else {
        if !dest_path.ends_with(FileHandler::FILE_EXTENSION_STR) {
            println!("Invalid file: {}", dest_path);
            return Ok(Some(dest_path));
        }
        dest_path = dest_path.replace(FileHandler::FILE_EXTENSION_STR, "");
    }
    let dest_path = path::PathBuf::from(dest_path);
    process_file(path, &dest_path, key, xrc, preserve, to_encrypt, n_jobs)?;
    Ok(None)
}

fn process_file(
    src_path: &path::PathBuf,
    dest_path: &path::PathBuf,
    key: &String,
    xrc: &Arc<XORCryptor>,
    preserve: bool,
    to_encrypt: bool,
    n_jobs: usize,
) -> Result<bool, Box<dyn Error>> {
    if fs::metadata(src_path)?.len() == 0 {
        if !preserve {
            fs::remove_file(src_path)?;
        }
        return Ok(true);
    }
    let mut file_handler = FileHandler::new(src_path, to_encrypt)?;
    let mut dest_file = fs::File::create(dest_path)?;

    validate_signature(
        &xrc.get_cipher(),
        key.as_bytes(),
        to_encrypt,
        &mut dest_file,
        &mut file_handler,
    )?;

    let total = file_handler.get_total_chunks();
    let (tx_id, rx_id) = sync::mpsc::channel::<i32>();
    let (tx_tr, rx_tr) = sync::mpsc::channel::<bool>();
    let (tx_sb, rx_sb) = sync::mpsc::channel::<Box<Vec<u8>>>();

    FileHandler::dispatch_writer_thread(Box::new(dest_file), total, tx_tr, rx_id, rx_sb)?;

    let (mut i, n_jobs) = (0u64, if n_jobs > 1 { n_jobs / 2 } else { 1 });
    loop {
        let mut handles = Vec::<JoinHandle<()>>::new();
        for _ in 0..n_jobs {
            let xrc = xrc.clone();
            let buffer = file_handler.read_buffer(i)?;
            let (tx, tx_sb) = (tx_id.clone(), tx_sb.clone());

            handles.push(thread::spawn(move || {
                let mut buffer = buffer;
                if to_encrypt {
                    xrc.encrypt_vec(buffer.as_mut());
                } else {
                    xrc.decrypt_vec(buffer.as_mut());
                }
                tx.send(i as i32).unwrap();
                tx_sb.send(buffer).unwrap();
            }));

            i += 1;
            if i == total {
                break;
            }
        }
        for h in handles {
            h.join().unwrap();
        }
        if i == total {
            break;
        }
    }

    let signal = rx_tr.recv().unwrap(); // Wait for writer thread
    if signal && !preserve {
        fs::remove_file(src_path)?;
    }
    Ok(signal)
}

fn validate_signature(
    cipher: &Vec<u8>,
    key: &[u8],
    to_encrypt: bool,
    dest_file: &mut fs::File,
    file_handler: &mut FileHandler,
) -> Result<(), Box<dyn Error>> {
    let mut mac = HmacSha256::new_from_slice(cipher).unwrap();
    mac.update(key);
    let hash = mac.clone().finalize().into_bytes();

    Ok(if to_encrypt {
        dest_file.write(&hash.as_ref())?;
    } else {
        let f_hash = file_handler.read_hash()?;
        mac.verify_slice(&f_hash.as_ref()[..])?;
    })
}
