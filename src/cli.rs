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
    collections::{HashMap, VecDeque},
    fs, path, thread,
};

use clap::{Arg, ArgAction, Command};
use path_absolutize::*;

use crate::file_handler::FileHandler;
use crate::logger::Logger;

pub struct CliArgs {
    preserve: bool,
    to_encrypt: bool,
    paths: Vec<path::PathBuf>,
    log_path: path::PathBuf,
    n_jobs: usize,
}

impl CliArgs {
    const ENCRYPT_CMD_ID: &'static str = "encrypt";
    const ENCRYPT_CMD_SHORT: char = 'e';

    const DECRYPT_CMD_ID: &'static str = "decrypt";
    const DECRYPT_CMD_SHORT: char = 'd';

    const RECURSIVE_CMD_ID: &'static str = "recursive";
    const RECURSIVE_CMD_SHORT: char = 'r';

    const PRESERVE_SRC_CMD_ID: &'static str = "preserve";
    const PRESERVE_SRC_CMD_SHORT: char = 'p';

    const JOB_CMD_ID: &'static str = "jobs";
    const JOB_CMD_SHORT: char = 'j';

    const FILES_CMD_ID: &'static str = "files";

    pub fn parse_args<'a>() -> Result<CliArgs, &'a str> {
        let matches = CliArgs::get_command().get_matches();

        let encrypt = matches.get_flag(CliArgs::ENCRYPT_CMD_ID);
        let decrypt = matches.get_flag(CliArgs::DECRYPT_CMD_ID);
        if encrypt == decrypt {
            return Err("Encrypt and Decrypt both exists, select one");
        }
        let recursive = matches.get_flag(CliArgs::RECURSIVE_CMD_ID);
        let preserve = matches.get_flag(CliArgs::PRESERVE_SRC_CMD_ID);

        let t_count = thread::available_parallelism();
        let mut n_jobs: usize = if t_count.is_ok() {
            t_count.unwrap().get()
        } else {
            4usize // default 4 jobs
        };

        let jobs = matches.get_one::<String>(CliArgs::JOB_CMD_ID);
        if jobs.is_some() {
            n_jobs = jobs.unwrap().clone().parse::<usize>().unwrap();
        }

        let paths = matches
            .get_many::<String>(CliArgs::FILES_CMD_ID)
            .unwrap_or_default()
            .map(|f| f.clone())
            .collect::<Vec<_>>();
        if paths.is_empty() {
            return Err("No files/folders found");
        }
        let log_path_ref = path::PathBuf::from(paths[0].clone());

        let mut files = HashMap::<path::PathBuf, u8>::new();
        CliArgs::list_files(&paths, &mut files, recursive, encrypt);
        if files.is_empty() {
            return Err("No files/folders found");
        }

        let mut list = Vec::<path::PathBuf>::new();
        for (path, _) in files {
            list.push(path);
        }

        Ok(CliArgs {
            preserve,
            to_encrypt: encrypt,
            paths: list,
            log_path: log_path_ref,
            n_jobs,
        })
    }

    fn get_command() -> Command {
        Command::new(env!("CARGO_PKG_NAME"))
            .version(env!("CARGO_PKG_VERSION"))
            .author(env!("CARGO_PKG_AUTHORS"))
            .about(env!("CARGO_PKG_DESCRIPTION"))
            .arg(
                Arg::new(CliArgs::ENCRYPT_CMD_ID)
                    .short(CliArgs::ENCRYPT_CMD_SHORT)
                    .long(CliArgs::ENCRYPT_CMD_ID)
                    .help("Encrypt")
                    .required_unless_present(CliArgs::DECRYPT_CMD_ID)
                    .action(ArgAction::SetTrue),
            )
            .arg(
                Arg::new(CliArgs::DECRYPT_CMD_ID)
                    .short(CliArgs::DECRYPT_CMD_SHORT)
                    .long(CliArgs::DECRYPT_CMD_ID)
                    .help("Decrypt")
                    .required_unless_present(CliArgs::ENCRYPT_CMD_ID)
                    .action(ArgAction::SetTrue),
            )
            .arg(
                Arg::new(CliArgs::FILES_CMD_ID)
                    .help("Files and folders to process")
                    .required(true)
                    .action(ArgAction::Append),
            )
            .arg(
                Arg::new(CliArgs::PRESERVE_SRC_CMD_ID)
                    .short(CliArgs::PRESERVE_SRC_CMD_SHORT)
                    .help("If set, does not delete the source file")
                    .action(ArgAction::SetTrue),
            )
            .arg(
                Arg::new(CliArgs::RECURSIVE_CMD_ID)
                    .short(CliArgs::RECURSIVE_CMD_SHORT)
                    .help("Recursively iterate folders if present")
                    .action(ArgAction::SetTrue),
            )
            .arg(
                Arg::new(CliArgs::JOB_CMD_ID)
                    .short(CliArgs::JOB_CMD_SHORT)
                    .help("No. of jobs")
                    .action(ArgAction::Set),
            )
    }

    fn list_files(
        paths: &Vec<String>,
        path_list: &mut HashMap<path::PathBuf, u8>,
        recursive: bool,
        encrypt: bool,
    ) {
        for path in paths {
            let path = path::PathBuf::from(path);
            let path_meta = fs::metadata(path.clone());
            if path_meta.is_err() {
                println!("Unable to read metadata: {:?}", path);
                continue;
            }

            let path_meta = path_meta.unwrap();
            if path_meta.is_file() {
                if path.file_name().unwrap() == Logger::LOGGER_FILE {
                    continue;
                }
                path_list.insert(path.absolutize().unwrap().to_path_buf(), 0u8);
                continue;
            }
            if path_meta.is_dir() {
                if recursive {
                    CliArgs::recursive_itr_dirs(path, path_list, encrypt);
                } else {
                    let list = fs::read_dir(path.clone());
                    if list.is_err() {
                        println!("Error reading dir: {:?}", path);
                        continue;
                    }
                    let list = list.unwrap();
                    for entry in list {
                        if entry.is_err() {
                            println!("Error: Unable to read file");
                            continue;
                        }

                        let entry = entry.unwrap().path().clone();
                        let entry_meta = fs::metadata(entry.clone());
                        if entry_meta.is_err() {
                            println!("Unable to read file metadata: {:?}", entry);
                            continue;
                        }

                        let entry_meta = entry_meta.unwrap();
                        if entry_meta.is_dir() {
                            continue;
                        }
                        if entry_meta.is_file() {
                            if entry.file_name().unwrap() == Logger::LOGGER_FILE {
                                continue;
                            }
                            let extension = entry.extension();
                            if extension == None {
                                if encrypt {
                                    path_list
                                        .insert(entry.absolutize().unwrap().to_path_buf(), 0u8);
                                }
                                continue;
                            }

                            let extension = extension.unwrap();
                            if encrypt && extension != FileHandler::FILE_EXTENSION {
                                path_list.insert(entry.absolutize().unwrap().to_path_buf(), 0u8);
                                continue;
                            }
                            if !encrypt && extension == FileHandler::FILE_EXTENSION {
                                path_list.insert(entry.absolutize().unwrap().to_path_buf(), 0u8);
                            }
                        }
                    }
                }
            }
        }
    }

    fn recursive_itr_dirs(
        root_path: path::PathBuf,
        list: &mut HashMap<path::PathBuf, u8>,
        to_encrypt: bool,
    ) {
        let mut q = VecDeque::<path::PathBuf>::new();
        q.push_back(root_path);
        while !q.is_empty() {
            let path = q.front().unwrap().clone();
            q.pop_front();

            let paths = fs::read_dir(path.clone());
            if paths.is_err() {
                println!("Error: Unable to read dir: {:?}", path);
                continue;
            }

            let paths = paths.unwrap();
            for entry in paths {
                if entry.is_err() {
                    continue;
                }

                let entry = entry.unwrap().path();
                let metadata = fs::metadata(entry.clone());
                if metadata.is_err() {
                    println!("Unable read file: {:?}", entry);
                    continue;
                }

                let metadata = metadata.unwrap();
                if metadata.is_dir() {
                    q.push_back(entry.clone());
                }
                if metadata.is_file() {
                    if entry.file_name().unwrap() == Logger::LOGGER_FILE {
                        continue;
                    }
                    let extension = entry.extension();
                    if extension == None {
                        if to_encrypt {
                            list.insert(entry.absolutize().unwrap().to_path_buf(), 0u8);
                        }
                        continue;
                    }

                    let extension = extension.unwrap();
                    if to_encrypt && extension != FileHandler::FILE_EXTENSION {
                        list.insert(entry.absolutize().unwrap().to_path_buf(), 0u8);
                        continue;
                    }
                    if !to_encrypt && extension == FileHandler::FILE_EXTENSION {
                        list.insert(entry.absolutize().unwrap().to_path_buf(), 0u8);
                    }
                }
            }
        }
    }

    pub fn is_preserve(&self) -> bool {
        self.preserve
    }

    pub fn to_encrypt(&self) -> bool {
        self.to_encrypt
    }

    pub fn get_path_count(&self) -> usize {
        self.paths.len()
    }

    pub fn get_jobs(&self) -> usize {
        self.n_jobs
    }

    pub fn get_log_path(&self) -> &path::PathBuf {
        &self.log_path
    }

    pub fn get_paths(&self) -> Vec<Vec<path::PathBuf>> {
        let mut pool = Vec::<Vec<path::PathBuf>>::new();
        for _ in 0..self.n_jobs {
            pool.push(Vec::<path::PathBuf>::new());
        }
        for i in 0..self.paths.len() {
            pool[i % self.n_jobs].push(self.paths[i].clone());
        }
        pool
    }
}
