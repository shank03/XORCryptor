use err::AppResult;

mod app;
mod cli;
mod err;
mod file_handler;
mod job;
mod logger;
mod xrc;

fn main() {
    match run() {
        Err(e) => println!("Error: {e}"),
        _ => (),
    };
}

fn run() -> AppResult<()> {
    let mut app = app::App::init()?;
    app.run()
}
