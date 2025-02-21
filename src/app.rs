use std::{
    path,
    sync::{Arc, Mutex},
    thread::{self, JoinHandle},
};

use indicatif::{MultiProgress, ProgressBar, ProgressStyle};

use crate::{
    cli::CliArgs,
    err::{AppError, AppResult},
    job::Job,
    logger::Logger,
    xrc::Xrc,
};

pub struct App {
    config: CliArgs,
    total_paths: usize,
    logger: Arc<Mutex<Logger>>,
}

impl App {
    pub fn init() -> AppResult<Self> {
        let config = CliArgs::parse_args()?;
        let total_paths = config.get_path_count();
        let logger = Arc::new(Mutex::new(Logger::init(config.get_log_path())));

        Ok(Self {
            config,
            total_paths,
            logger,
        })
    }

    pub fn run(&mut self) -> AppResult<()> {
        self.logger
            .lock()
            .unwrap()
            .log_p(format!("{} files found.\n", self.total_paths).as_str());

        self.logger
                .lock()
                .unwrap()
                .log_p(if self.config.is_legacy() {
                    "Using LEGACY_MODE [V1]\n"
                } else {
                    "Using V2 - NOTE: if you used previous version to encrypt/decrypt your files, please use legacy flag '-l'\n"
                });

        let key = self.get_key()?;

        let mut xrc = Xrc::legacy(&key)?;
        let key: Arc<str> = key.into();
        if !self.config.is_legacy() {
            xrc = Xrc::V2(key.clone());
        }

        let pool = self.config.get_paths();
        let progress_bars = self.prepare_progress(&pool);

        let mut handles = Vec::<JoinHandle<AppResult<()>>>::new();
        for (path_list, progress) in pool.into_iter().zip(progress_bars) {
            if path_list.is_empty() {
                break;
            }

            let key = key.clone();
            let xrc = xrc.clone();
            let logger = self.logger.clone();

            let preserve = self.config.should_preserve();
            let to_encrypt = self.config.to_encrypt();
            let n_jobs = self.config.get_jobs();

            handles.push(thread::spawn(move || {
                Job::new(
                    path_list, progress, key, xrc, logger, preserve, to_encrypt, n_jobs,
                )
                .run()
            }));
        }
        for h in handles {
            if let Err(err) = h.join().unwrap() {
                self.logger
                    .lock()
                    .unwrap()
                    .log(format!("Error processing chunk: {:?}", err).as_str());
            }
        }
        self.logger.lock().unwrap().inform();

        Ok(())
    }

    fn get_key(&mut self) -> AppResult<String> {
        let key = rpassword::prompt_password("Enter key: ").map_err(|e| AppError::IoError(e))?;

        Ok(key.trim().replace("\n", "").replace("\r", ""))
    }

    fn prepare_progress(&mut self, pool: &Vec<Vec<path::PathBuf>>) -> Vec<ProgressBar> {
        let mut progress_bars = Vec::<ProgressBar>::new();
        let multi_pr = MultiProgress::new();
        let style = ProgressStyle::with_template(
            "[{elapsed}] [{bar:30.cyan/yellow}] {pos:>6}/{len:6} {msg}",
        )
        .unwrap()
        .progress_chars("=>-");

        for i in 0..self.config.get_jobs() {
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
            progress_bars.push(pb);
        }

        let _ = multi_pr.println(if self.config.to_encrypt() {
            self.logger.lock().unwrap().log("\nEncrypting...");
            "\nEncrypting..."
        } else {
            self.logger.lock().unwrap().log("\nDecrypting...");
            "\nDecrypting..."
        });
        progress_bars
    }
}
