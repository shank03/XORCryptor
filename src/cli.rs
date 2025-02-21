use std::{
    collections::{HashSet, VecDeque},
    fs, path, thread,
};

use clap::{Arg, ArgAction, Command};
use path_absolutize::*;

use crate::{
    err::{AppError, AppResult},
    file_handler::FileHandler,
    logger::Logger,
};

pub struct CliArgs {
    preserve: bool,
    to_encrypt: bool,
    paths: Vec<path::PathBuf>,
    log_path: path::PathBuf,
    n_jobs: usize,
    legacy: bool,
}

impl CliArgs {
    const ENCRYPT_CMD_ID: &'static str = "encrypt";
    const ENCRYPT_CMD_SHORT: char = 'e';

    const DECRYPT_CMD_ID: &'static str = "decrypt";
    const DECRYPT_CMD_SHORT: char = 'd';

    const LEGACY_CMD_ID: &'static str = "legacy";
    const LEGACY_CMD_SHORT: char = 'l';

    const RECURSIVE_CMD_ID: &'static str = "recursive";
    const RECURSIVE_CMD_SHORT: char = 'r';

    const PRESERVE_SRC_CMD_ID: &'static str = "preserve";
    const PRESERVE_SRC_CMD_SHORT: char = 'p';

    const JOB_CMD_ID: &'static str = "jobs";
    const JOB_CMD_SHORT: char = 'j';

    const FILES_CMD_ID: &'static str = "files";

    pub fn parse_args<'a>() -> AppResult<CliArgs> {
        let matches = CliArgs::get_command().get_matches();

        let legacy = matches.get_flag(CliArgs::LEGACY_CMD_ID);

        let encrypt = matches.get_flag(CliArgs::ENCRYPT_CMD_ID);
        let decrypt = matches.get_flag(CliArgs::DECRYPT_CMD_ID);
        if encrypt == decrypt {
            return Err(AppError::IncorrectFlags);
        }
        let recursive = matches.get_flag(CliArgs::RECURSIVE_CMD_ID);
        let preserve = matches.get_flag(CliArgs::PRESERVE_SRC_CMD_ID);

        let t_count = thread::available_parallelism();
        let mut n_jobs = t_count.map(|v| v.get()).unwrap_or(4);

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
            return Err(AppError::NoFilesOrFolder);
        }
        let log_path_ref = path::PathBuf::from(paths[0].clone());

        let mut files = HashSet::<path::PathBuf>::new();
        CliArgs::list_files(&paths, &mut files, recursive, encrypt);

        if files.is_empty() {
            return Err(AppError::NoFilesOrFolder);
        }

        let list: Vec<_> = files.into_iter().collect();

        Ok(CliArgs {
            preserve,
            to_encrypt: encrypt,
            paths: list,
            log_path: log_path_ref,
            n_jobs,
            legacy,
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
                Arg::new(CliArgs::LEGACY_CMD_ID)
                    .short(CliArgs::LEGACY_CMD_SHORT)
                    .long(CliArgs::LEGACY_CMD_ID)
                    .help("Legacy for older v1")
                    .long_help("Since xor_cryptor lib has been upgraded to v2 which is different and safer algorithm, select legacy flag if your data was encrypted with v1 xor_cryptor.")
                    .required(false)
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

    /// Process all the directories and files
    /// mentioned in the CLI arguments.
    ///
    /// Additionally, recurrsively scan the directory if
    /// the `-r` flag exists.
    fn list_files(
        paths: &Vec<String>,
        path_list: &mut HashSet<path::PathBuf>,
        recursive: bool,
        encrypt: bool,
    ) {
        for path in paths.into_iter() {
            let path = path::PathBuf::from(path);
            let path_meta = match fs::metadata(path.clone()) {
                Ok(m) => m,
                Err(err) => {
                    println!("Unable to read metadata: {:?} - {:?}", path, err);
                    continue;
                }
            };

            if path_meta.is_file() {
                // skip log file
                if path.file_name().unwrap_or_default() == Logger::LOGGER_FILE {
                    continue;
                }
                path_list.insert(path.absolutize().unwrap().to_path_buf());
                continue;
            }

            if path_meta.is_dir() {
                if recursive {
                    CliArgs::recursive_itr_dirs(path, path_list, encrypt);
                    continue;
                }

                // scan directory at depth=1
                let list = match fs::read_dir(path.clone()) {
                    Ok(l) => l,
                    Err(err) => {
                        println!("Error reading dir: {:?} - {:?}", path, err);
                        continue;
                    }
                };

                for entry in list {
                    let entry = match entry {
                        Ok(e) => e,
                        Err(err) => {
                            println!("Error: Unable to read dir - {:?}", err);
                            continue;
                        }
                    };

                    let entry_path = entry.path();
                    let entry_meta = match fs::metadata(entry_path.clone()) {
                        Ok(m) => m,
                        Err(err) => {
                            println!("Unable to read file metadata: {:?} - {:?}", entry_path, err);
                            continue;
                        }
                    };

                    // skip if directory as `-r` not present
                    if entry_meta.is_dir() {
                        continue;
                    }

                    if entry_meta.is_file() {
                        // skip log file
                        if entry_path.file_name().unwrap_or_default() == Logger::LOGGER_FILE {
                            continue;
                        }

                        match entry_path.extension() {
                            Some(ext) => {
                                if encrypt && ext != FileHandler::FILE_EXTENSION {
                                    path_list
                                        .insert(entry_path.absolutize().unwrap().to_path_buf());
                                    continue;
                                }
                                if !encrypt && ext == FileHandler::FILE_EXTENSION {
                                    path_list
                                        .insert(entry_path.absolutize().unwrap().to_path_buf());
                                }
                            }
                            None => {
                                if encrypt {
                                    path_list
                                        .insert(entry_path.absolutize().unwrap().to_path_buf());
                                }
                                continue;
                            }
                        };
                    }
                }
            }
        }
    }

    /// Recursively scan the directories
    ///
    /// Uses BFS
    fn recursive_itr_dirs(
        root_path: path::PathBuf,
        list: &mut HashSet<path::PathBuf>,
        to_encrypt: bool,
    ) {
        let mut q = VecDeque::<path::PathBuf>::new();
        q.push_back(root_path);

        while let Some(path) = q.pop_front() {
            let paths = match fs::read_dir(path.clone()) {
                Ok(p) => p,
                Err(err) => {
                    println!("Error: Unable to read dir: {:?} - {:?}", path, err);
                    continue;
                }
            };

            for entry in paths {
                let entry = match entry {
                    Ok(e) => e,
                    Err(err) => {
                        println!("Failed entry: {:?}", err);
                        continue;
                    }
                };

                let entry_path = entry.path();
                let metadata = match fs::metadata(entry_path.clone()) {
                    Ok(m) => m,
                    Err(err) => {
                        println!("Unable read file: {:?} - {:?}", entry_path, err);
                        continue;
                    }
                };

                if metadata.is_dir() {
                    q.push_back(entry_path.clone());
                }
                if metadata.is_file() {
                    // skip log file
                    if entry_path.file_name().unwrap_or_default() == Logger::LOGGER_FILE {
                        continue;
                    }

                    match entry_path.extension() {
                        Some(ext) => {
                            if to_encrypt && ext != FileHandler::FILE_EXTENSION {
                                list.insert(entry_path.absolutize().unwrap().to_path_buf());
                                continue;
                            }
                            if !to_encrypt && ext == FileHandler::FILE_EXTENSION {
                                list.insert(entry_path.absolutize().unwrap().to_path_buf());
                            }
                        }
                        None => {
                            if to_encrypt {
                                list.insert(entry_path.absolutize().unwrap().to_path_buf());
                            }
                            continue;
                        }
                    }
                }
            }
        }
    }

    pub fn should_preserve(&self) -> bool {
        self.preserve
    }

    pub fn to_encrypt(&self) -> bool {
        self.to_encrypt
    }

    pub fn is_legacy(&self) -> bool {
        self.legacy
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
