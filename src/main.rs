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
    sync::{self, Arc, Mutex},
    thread::{self, JoinHandle},
};

use hmac::{Hmac, Mac};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use sha2::Sha256;
use xor_cryptor::XORCryptor;

use cli::CliArgs;
use file_handler::FileHandler;
use logger::Logger;

mod cli;
mod file_handler;
mod logger;

type HmacSha256 = Hmac<Sha256>;

fn main() {
    let config = CliArgs::parse_args();
    if config.is_err() {
        println!("Error: {}", config.err().unwrap());
        return;
    }
    let config = config.unwrap();
    let total_paths = config.get_path_count();
    let mut logger = Logger::init(config.get_log_path().clone());

    logger.log_p(format!("{} files found.\n", total_paths).as_str());
    let (key, xrc) = match get_key(&mut logger) {
        Some(value) => value,
        None => return,
    };
    let xrc = Arc::new(xrc);
    let key = Arc::new(key);

    let pool = config.get_paths();
    let progress_bars = prepare_progress(&config, &mut logger, &pool);

    let mut pbr_idx = 0usize;
    let mut handles = Vec::<JoinHandle<()>>::new();
    let logger = Arc::new(Mutex::new(logger));
    for path_list in pool {
        if path_list.is_empty() {
            break;
        }

        let (key, xrc, logger) = (key.clone(), xrc.clone(), logger.clone());
        let (preserve, to_encrypt, n_jobs) =
            (config.is_preserve(), config.to_encrypt(), config.get_jobs());

        let pr_br = progress_bars[pbr_idx].clone();
        handles.push(thread::spawn(move || {
            job(
                path_list, pr_br, key, xrc, logger, preserve, to_encrypt, n_jobs,
            );
        }));
        pbr_idx += 1;
    }
    for h in handles {
        h.join().unwrap();
    }
    logger.lock().unwrap().inform();
}

fn get_key(logger: &mut Logger) -> Option<(String, XORCryptor)> {
    println!("Enter key: ");
    let mut key = String::new();
    let len = stdin().read_line(&mut key);
    if len.is_err() {
        logger.log_p("Error reading key input");
        return None;
    }

    let key = key.trim().replace("\n", "").replace("\r", "");
    let xrc = XORCryptor::new(&key);
    if xrc.is_err() {
        logger.log_p(format!("Error: {}", xrc.err().unwrap()).as_str());
        return None;
    }
    Some((key.clone(), xrc.unwrap()))
}

fn prepare_progress(
    config: &CliArgs,
    logger: &mut Logger,
    pool: &Vec<Vec<path::PathBuf>>,
) -> Vec<Box<ProgressBar>> {
    let mut progress_bars = Vec::<Box<ProgressBar>>::new();
    let multi_pr = MultiProgress::new();
    let style =
        ProgressStyle::with_template("[{elapsed}] [{bar:30.cyan/yellow}] {pos:>6}/{len:6} {msg}")
            .unwrap()
            .progress_chars("=>-");

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
        logger.log("\nEncrypting...");
        "\nEncrypting..."
    } else {
        logger.log("\nDecrypting...");
        "\nDecrypting..."
    });
    progress_bars
}

fn job(
    path_list: Vec<path::PathBuf>,
    pr_br: Box<ProgressBar>,
    key: Arc<String>,
    xrc: Arc<XORCryptor>,
    logger: Arc<Mutex<Logger>>,
    preserve: bool,
    to_encrypt: bool,
    n_jobs: usize,
) {
    let list = path_list;
    let pbr = pr_br;
    pbr.set_position(0);
    for path in list {
        pbr.set_message(String::from(path.file_name().unwrap().to_str().unwrap()));
        match validate_file(
            &path,
            key.as_ref(),
            &xrc,
            &logger,
            preserve,
            to_encrypt,
            n_jobs,
        ) {
            Ok(op_path) => {
                if op_path.is_some() {
                    logger.lock().unwrap().inform_user_log();
                    logger
                        .lock()
                        .unwrap()
                        .log(format!("Invalid file: {}", op_path.unwrap()).as_str());
                }
            }
            Err(err) => {
                logger.lock().unwrap().inform_user_log();
                logger.lock().unwrap().log(
                    format!("Error: {}: {}", path.to_str().unwrap(), err.to_string()).as_str(),
                );
            }
        }
        pbr.inc(1);
    }
    pbr.finish_with_message("Done");
}

fn validate_file(
    path: &path::PathBuf,
    key: &String,
    xrc: &Arc<XORCryptor>,
    logger: &Arc<Mutex<Logger>>,
    preserve: bool,
    to_encrypt: bool,
    n_jobs: usize,
) -> Result<Option<String>, Box<dyn Error>> {
    let mut dest_path = String::from(path.clone().to_str().unwrap());
    if to_encrypt {
        if dest_path.ends_with(FileHandler::FILE_EXTENSION_STR) {
            return Ok(Some(dest_path));
        }
        dest_path.push_str(FileHandler::FILE_EXTENSION_STR);
    } else {
        if !dest_path.ends_with(FileHandler::FILE_EXTENSION_STR) {
            return Ok(Some(dest_path));
        }
        dest_path = dest_path.replace(FileHandler::FILE_EXTENSION_STR, "");
    }
    let dest_path = path::PathBuf::from(dest_path);
    process_file(
        path, &dest_path, key, xrc, logger, preserve, to_encrypt, n_jobs,
    )?;
    Ok(None)
}

fn process_file(
    src_path: &path::PathBuf,
    dest_path: &path::PathBuf,
    key: &String,
    xrc: &Arc<XORCryptor>,
    logger: &Arc<Mutex<Logger>>,
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

    let validation_result = validate_signature(
        unsafe { xrc.get_cipher().align_to::<u8>().1 },
        key.as_bytes(),
        to_encrypt,
        &mut dest_file,
        &mut file_handler,
    );

    if validation_result.is_err() {
        fs::remove_file(dest_path)?;
        return Err(validation_result.err().unwrap());
    }

    let pool_size = file_handler.get_total_chunks();
    let (tx_id, rx_id) = sync::mpsc::channel::<usize>();
    let (tx_trggr, rx_trggr) = sync::mpsc::channel::<usize>();
    let (tx_sig, rx_sig) = sync::mpsc::channel::<bool>();
    let (tx_sb, rx_sb) = sync::mpsc::channel::<Vec<u8>>();

    FileHandler::dispatch_writer_thread(dest_file, pool_size, tx_sig, rx_trggr, rx_id, rx_sb);

    let (mut i, n_jobs) = (0usize, 1usize.max(n_jobs / 2));
    loop {
        let mut handles = Vec::<JoinHandle<()>>::new();
        for _ in 0..n_jobs {
            let xrc = xrc.clone();
            let buffer = file_handler.read_buffer(i as u64)?;
            let (tx_id, tx_sb) = (tx_id.clone(), tx_sb.clone());

            handles.push(thread::spawn(move || {
                let b_res = if to_encrypt {
                    xrc.encrypt_vec(*buffer)
                } else {
                    xrc.decrypt_vec(*buffer)
                };
                tx_id.send(i).unwrap();
                tx_sb.send(b_res).unwrap();
            }));

            i += 1;
            if i == pool_size {
                break;
            }
        }
        let chunks = handles.len();
        for h in handles.into_iter() {
            h.join().unwrap();
        }
        tx_trggr.send(chunks).unwrap();
        if rx_sig.recv().unwrap() {
            break;
        }
        if i == pool_size {
            tx_trggr.send(0).unwrap();
            break;
        }
    }

    let signal = rx_sig.recv().unwrap(); // Wait for writer thread
    if !signal {
        logger
            .lock()
            .unwrap()
            .log(format!("Please retry: {:?}", src_path).as_str());
    }
    if signal && !preserve {
        fs::remove_file(src_path)?;
    }
    Ok(signal)
}

fn validate_signature(
    cipher: &[u8],
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
