use std::{
    fs,
    io::{Read, Write},
    path,
    sync::mpsc::{Receiver, Sender},
    thread,
};

use crate::err::{AppError, AppResult};

pub struct FileHandler {
    src_file: fs::File,
    total_chunks: u64,
    last_chunk_len: u64,
}

impl FileHandler {
    pub const FILE_EXTENSION: &'static str = "xrc";
    pub const FILE_EXTENSION_STR: &'static str = ".xrc";

    const CHUNK_SIZE: u64 = 1024u64 * 1024u64 * 64u64;
    const HASH_LEN: usize = 32usize;

    pub fn new(src_path: &path::PathBuf, to_encrypt: bool) -> AppResult<Self> {
        let src_file = fs::File::open(src_path).map_err(|e| AppError::IoError(e))?;

        let metadata = src_file.metadata().map_err(|e| AppError::IoError(e))?;
        let mut length = metadata.len();
        if !to_encrypt {
            length -= FileHandler::HASH_LEN as u64;
        }
        let mut total_chunks = length / FileHandler::CHUNK_SIZE;
        let mut last_chunk_len = length % FileHandler::CHUNK_SIZE;
        if last_chunk_len != 0 {
            total_chunks += 1;
        } else {
            last_chunk_len = FileHandler::CHUNK_SIZE;
        }
        Ok(FileHandler {
            src_file,
            total_chunks,
            last_chunk_len,
        })
    }

    pub fn get_total_chunks(&self) -> usize {
        self.total_chunks as usize
    }

    pub fn read_hash(&mut self) -> AppResult<Vec<u8>> {
        let mut buffer = vec![0u8; FileHandler::HASH_LEN];
        self.src_file
            .read_exact(&mut buffer)
            .map_err(|e| AppError::IoError(e))?;
        Ok(buffer)
    }

    pub fn read_buffer(&mut self, idx: u64) -> AppResult<Vec<u8>> {
        let mut buffer = vec![
            0u8;
            (if idx == self.total_chunks - 1u64 {
                self.last_chunk_len
            } else {
                FileHandler::CHUNK_SIZE
            }) as usize
        ];

        self.src_file
            .read_exact(&mut buffer)
            .map_err(|e| AppError::IoError(e))?;
        Ok(buffer)
    }

    pub fn dispatch_writer_thread(
        mut dest_file: fs::File,
        pool_size: usize,
        tx_signal: Sender<bool>,
        rx_chunks: Receiver<usize>,
        rx_buf_id: Receiver<usize>,
        rx_buffer: Receiver<Vec<u8>>,
    ) {
        thread::spawn(move || {
            let mut broken = false;
            let mut pool: Vec<Option<Vec<u8>>> = vec![None; pool_size as usize];

            for chunk_sig in rx_chunks {
                if chunk_sig == 0 {
                    break;
                }

                let (mut chunks, mut ref_id) = (chunk_sig, usize::MAX);
                while chunks != 0 {
                    let recv_id = rx_buf_id.recv().unwrap();
                    ref_id = ref_id.min(recv_id);

                    let buffer = rx_buffer.recv().unwrap();
                    pool[recv_id] = Some(buffer);
                    chunks -= 1;
                }

                chunks = chunk_sig;
                while chunks != 0 && !broken {
                    if let Some(buf) = &pool[ref_id] {
                        broken = dest_file.write_all(&buf).is_err();
                        pool[ref_id] = None;
                    }
                    ref_id += 1;
                    chunks -= 1;
                }

                tx_signal.send(broken).unwrap();
                if broken {
                    break;
                }
            }

            for i in 0..pool.len() {
                pool[i] = None;
            }

            tx_signal.send(!broken).unwrap();
        });
    }
}
