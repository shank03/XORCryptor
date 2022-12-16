use std::{fs, io::Write, path, str::FromStr};

use path_absolutize::Absolutize;

pub struct Logger {
    logger_file: Option<fs::File>,
    file_path: path::PathBuf,
    inform_user_log: bool,
}

impl Logger {
    pub const LOGGER_FILE: &'static str = "xrc_log.txt";

    pub fn init(path: path::PathBuf) -> Self {
        let log_path = path.join(path::PathBuf::from_str(Logger::LOGGER_FILE).unwrap());
        let file = fs::File::create(log_path.absolutize().unwrap());
        Logger {
            logger_file: if file.is_err() {
                None
            } else {
                Some(file.unwrap())
            },
            file_path: log_path,
            inform_user_log: false,
        }
    }

    pub fn log_p(&mut self, msg: &str) {
        self.log(msg);
        println!("{}", msg);
    }

    pub fn log(&mut self, msg: &str) {
        if self.logger_file.is_none() {
            return;
        }
        let _ = self
            .logger_file
            .as_ref()
            .unwrap()
            .write_all(format!("{}\n", msg).as_bytes());
    }

    pub fn inform_user_log(&mut self) {
        self.inform_user_log = true;
    }

    pub fn inform(&self) {
        if !self.inform_user_log {
            return;
        }
        println!(
            "There were some errors. Please check the logs at: {:?}",
            self.file_path
        );
    }
}
