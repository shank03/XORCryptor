use std::fmt::Display;

#[derive(Debug)]
pub enum AppError {
    IncorrectFlags,
    NoFilesOrFolder,
    IoError(std::io::Error),
    XrcError(xor_cryptor::err::XRCError),
    SignatureError(hmac::digest::MacError),
}

impl Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                AppError::IncorrectFlags =>
                    format!("[IncorrectFlags] Must be either Encrypt or Decrypt flag"),
                AppError::NoFilesOrFolder => format!("[NoFilesOrFolder] Empty list of files"),
                AppError::IoError(error) => format!("[IoError] {:?}", error),
                AppError::XrcError(xrcerror) => format!("[XrcError] {}", xrcerror),
                AppError::SignatureError(mac_error) =>
                    format!("[HmacError] {}", mac_error.to_string()),
            }
        )
    }
}

pub type AppResult<T> = Result<T, AppError>;
