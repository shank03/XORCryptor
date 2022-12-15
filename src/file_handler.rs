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
    fs,
    io::{Error, Read, Write},
    path,
    sync::mpsc::{Receiver, Sender},
    thread,
};

pub struct FileHandler {
    src_file: fs::File,
    total_chunks: u64,
    last_chunk_len: u64,
}

impl FileHandler {
    pub const FILE_EXTENSION: &'static str = "xrc";
    pub const FILE_EXTENSION_STR: &'static str = ".xrc";

    const CHUNK_SIZE: u64 = 1024u64 * 1024u64 * 64u64;

    pub fn new(src_path: &path::PathBuf, to_encrypt: bool) -> Result<Self, Error> {
        let src_file = fs::File::open(src_path)?;

        let mut length = src_file.metadata()?.len();
        if !to_encrypt {
            length -= 32;
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

    pub fn read_hash(&mut self) -> Result<Box<Vec<u8>>, Error> {
        let mut buffer = vec![0u8; 32usize];
        self.src_file.read_exact(&mut buffer)?;
        Ok(Box::new(buffer))
    }

    pub fn read_buffer(&mut self, idx: u64) -> Result<Box<Vec<u8>>, Error> {
        let mut buffer = vec![
            0u8;
            (if idx == self.total_chunks - 1u64 {
                self.last_chunk_len
            } else {
                FileHandler::CHUNK_SIZE
            }) as usize
        ];
        self.src_file.read_exact(&mut buffer)?;
        Ok(Box::new(buffer))
    }

    pub fn dispatch_writer_thread(
        dest_file: fs::File,
        pool_size: usize,
        tx_sig: Sender<bool>,
        rx_trggr: Receiver<usize>,
        rx_id: Receiver<usize>,
        rx_sb: Receiver<Vec<u8>>,
    ) {
        let mut dest_file = dest_file;
        thread::spawn(move || {
            let mut broken = false;
            let mut pool: Vec<Option<Vec<u8>>> = vec![None; pool_size as usize];
            for trg_sig in rx_trggr {
                if trg_sig == 0 {
                    break;
                }

                let (mut chunks, mut ref_idx) = (trg_sig, usize::MAX);
                while chunks != 0 {
                    let recv_idx = rx_id.recv().unwrap();
                    ref_idx = ref_idx.min(recv_idx);

                    let buffer = rx_sb.recv().unwrap();
                    pool[recv_idx] = Some(buffer);
                    chunks -= 1;
                }
                chunks = trg_sig;
                while chunks != 0 && !broken {
                    broken = dest_file
                        .write_all(pool[ref_idx].as_ref().unwrap())
                        .is_err();
                    pool[ref_idx] = None;
                    ref_idx += 1;
                    chunks -= 1;
                }
                tx_sig.send(broken).unwrap();
                if broken {
                    break;
                }
            }
            for i in 0..pool.len() {
                pool[i] = None;
            }
            tx_sig.send(!broken).unwrap();
        });
    }
}
