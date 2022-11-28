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
    pub const FILE_EXTENSION: &str = "xrc";
    pub const FILE_EXTENSION_STR: &str = ".xrc";

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

    pub fn get_total_chunks(&self) -> u64 {
        self.total_chunks
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
        dest_file: Box<fs::File>,
        pool_size: u64,
        tx_tr: Sender<bool>,
        rx_id: Receiver<i32>,
        rx_sb: Receiver<Box<Vec<u8>>>,
    ) -> Result<(), Error> {
        let mut dest_file = dest_file;
        thread::spawn(move || {
            let mut idx = 0i32;
            let mut pool: Vec<Option<Box<Vec<u8>>>> = vec![None; pool_size as usize];
            for rec in rx_id {
                let buffer = rx_sb.recv().unwrap();
                pool[rec as usize] = Some(buffer);
                if rec == idx {
                    while idx < (pool_size as i32) && pool[idx as usize] != None {
                        let _ = dest_file.write_all(pool[idx as usize].as_ref().unwrap());
                        pool[idx as usize] = None;
                        idx += 1;
                    }
                }
                if idx == pool_size as i32 {
                    break;
                }
            }
            tx_tr.send(true).unwrap();
        });
        Ok(())
    }
}
