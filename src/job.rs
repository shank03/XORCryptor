use std::{
    io::Write,
    path,
    sync::{mpsc, Arc, Mutex},
    thread::{self, JoinHandle},
};

use hmac::{Hmac, Mac};
use indicatif::ProgressBar;
use sha2::Sha256;

use crate::{
    err::{AppError, AppResult},
    file_handler::FileHandler,
    logger::Logger,
    xrc::Xrc,
};

pub struct Job {
    path_list: Vec<path::PathBuf>,
    progress: ProgressBar,
    key: Arc<str>,
    xrc: Xrc,
    logger: Arc<Mutex<Logger>>,
    preserve: bool,
    to_encrypt: bool,
    n_jobs: usize,
}

impl Job {
    pub fn new(
        path_list: Vec<path::PathBuf>,
        progress: ProgressBar,
        key: Arc<str>,
        xrc: Xrc,
        logger: Arc<Mutex<Logger>>,
        preserve: bool,
        to_encrypt: bool,
        n_jobs: usize,
    ) -> Self {
        Self {
            path_list,
            progress,
            key,
            xrc,
            logger,
            preserve,
            to_encrypt,
            n_jobs,
        }
    }

    pub fn run(&self) -> AppResult<()> {
        self.progress.set_position(0);
        for path in self.path_list.iter() {
            self.progress
                .set_message(String::from(path.file_name().unwrap().to_str().unwrap()));
            let dest_path = self.compute_dest_path(path.clone());

            match self.process_file(&path, &dest_path) {
                Ok(()) => self.logger.lock().unwrap().log(
                    format!(
                        "[{}] {:?} to {:?}",
                        if self.to_encrypt {
                            "Encrypt"
                        } else {
                            "Decrypt"
                        },
                        path,
                        dest_path,
                    )
                    .as_str(),
                ),
                Err(err) => {
                    let mut log = self.logger.lock().unwrap();
                    log.inform_user_log();
                    log.log(
                        format!("Error: {}: {}", path.to_str().unwrap(), err.to_string()).as_str(),
                    );
                }
            };
            self.progress.inc(1);
        }
        self.progress.finish_with_message("Done");

        Ok(())
    }

    fn compute_dest_path(&self, path: path::PathBuf) -> path::PathBuf {
        match path.extension() {
            Some(ext) => {
                let ext = ext.to_os_string();

                if self.to_encrypt {
                    if ext
                        .to_str()
                        .map(|e| e.ends_with(FileHandler::FILE_EXTENSION))
                        .unwrap_or(false)
                    {
                        return path;
                    }

                    let mut ext = ext;
                    ext.push(FileHandler::FILE_EXTENSION_STR);
                    return path.with_extension(ext);
                }

                // decrypt
                if !ext
                    .to_str()
                    .map(|e| e.ends_with(FileHandler::FILE_EXTENSION))
                    .unwrap_or(false)
                {
                    return path;
                }
            }
            None => {
                if self.to_encrypt {
                    return path.with_extension(FileHandler::FILE_EXTENSION);
                }
            }
        };

        path.with_extension("")
    }

    fn process_file(&self, src_path: &path::PathBuf, dest_path: &path::PathBuf) -> AppResult<()> {
        let metadata = std::fs::metadata(src_path).map_err(|e| AppError::IoError(e))?;
        let file_size = metadata.len();
        if file_size == 0 {
            if !self.preserve {
                let _ = std::fs::remove_file(src_path);
            }
            return Ok(());
        }
        let mut file_handler = FileHandler::new(src_path, self.to_encrypt)?;
        let mut dest_file = std::fs::File::create(dest_path).map_err(|e| AppError::IoError(e))?;

        if self.to_encrypt {
            self.insert_cipher_hash(src_path, &mut dest_file)?;
        } else {
            let file_hash = file_handler.read_hash()?;
            match self.validate_signature(dest_path, file_hash) {
                Err(e) => {
                    let _ = std::fs::remove_file(dest_path);
                    return Err(e);
                }
                _ => (),
            };
        }

        let pool_size = file_handler.get_total_chunks();
        let (tx_buf_id, rx_buf_id) = mpsc::channel::<usize>();
        let (tx_chunks, rx_chunks) = mpsc::channel::<usize>();
        let (tx_signal, rx_signal) = mpsc::channel::<bool>();
        let (tx_buffer, rx_buffer) = mpsc::channel::<Vec<u8>>();

        FileHandler::dispatch_writer_thread(
            dest_file, pool_size, tx_signal, rx_chunks, rx_buf_id, rx_buffer,
        );

        let (mut i, n_jobs) = (0usize, 1usize.max(self.n_jobs / 2));
        loop {
            let mut handles = Vec::<JoinHandle<AppResult<()>>>::new();
            for _ in 0..n_jobs {
                let buffer = file_handler.read_buffer(i as u64)?;
                let (tx_buf_id, tx_buffer) = (tx_buf_id.clone(), tx_buffer.clone());

                let to_encrypt = self.to_encrypt;
                let xrc = self.xrc.clone();

                handles.push(thread::spawn(move || {
                    let processed_buffer = if to_encrypt {
                        xrc.encrypt_vec(buffer)
                    } else {
                        xrc.decrypt_vec(buffer)
                    }?;
                    tx_buf_id.send(i).unwrap();
                    tx_buffer.send(processed_buffer).unwrap();
                    Ok(())
                }));

                i += 1;
                if i == pool_size {
                    break;
                }
            }
            let chunks = handles.len();
            for h in handles.into_iter() {
                if let Err(err) = h.join().unwrap() {
                    self.logger.lock().unwrap().log(
                        format!("[{:?}] - Error processing buffer: {:?}", src_path, err).as_str(),
                    );
                }
            }
            tx_chunks.send(chunks).unwrap();
            if rx_signal.recv().unwrap() {
                break;
            }
            if i == pool_size {
                tx_chunks.send(0).unwrap();
                break;
            }
        }

        let signal = rx_signal.recv().unwrap(); // Wait for writer thread
        if !signal {
            self.logger
                .lock()
                .unwrap()
                .log(format!("Please retry: {:?}", src_path).as_str());
        }
        if signal && !self.preserve {
            let _ = std::fs::remove_file(src_path);
        }
        Ok(())
    }

    fn insert_cipher_hash(
        &self,
        src_path: &path::PathBuf,
        dest_file: &mut std::fs::File,
    ) -> AppResult<()> {
        let cipher = self.xrc.get_cipher(src_path);
        let mut mac = Hmac::<Sha256>::new_from_slice(&cipher).unwrap();
        mac.update(self.key.as_bytes());

        let hash = mac.finalize().into_bytes();

        dest_file
            .write(hash.as_ref())
            .map_err(|e| AppError::IoError(e))?;

        Ok(())
    }

    fn validate_signature(&self, dest_path: &path::PathBuf, file_hash: Vec<u8>) -> AppResult<()> {
        let cipher = self.xrc.get_cipher(dest_path);
        let mut mac = Hmac::<Sha256>::new_from_slice(&cipher).unwrap();
        mac.update(self.key.as_bytes());

        mac.verify_slice(&file_hash)
            .map_err(|e| AppError::SignatureError(e))?;
        Ok(())
    }
}
