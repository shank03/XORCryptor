use std::{path, sync::Arc};

use xor_cryptor::{XORCryptor, V1};

use crate::err::{AppError, AppResult};

pub enum Xrc {
    V1(Arc<XORCryptor<V1>>),
    V2(Arc<str>),
}

impl Clone for Xrc {
    fn clone(&self) -> Self {
        match self {
            Xrc::V1(x) => Xrc::V1(Arc::clone(x)),
            Xrc::V2(s) => Xrc::V2(Arc::clone(s)),
        }
    }
}

impl Xrc {
    pub fn legacy(key: &str) -> AppResult<Self> {
        let xrc = XORCryptor::new(key).map_err(|e| AppError::XrcError(e))?;
        let xrc = Arc::new(xrc);
        Ok(Self::V1(xrc))
    }

    pub fn get_cipher(&self, file_path: &path::PathBuf) -> Vec<u8> {
        match self {
            Xrc::V1(xrc) => unsafe { xrc.get_cipher().align_to().1.to_vec() },
            Xrc::V2(key) => {
                let seed = self.compute_spice_seed(file_path);

                let mut xrc = XORCryptor::new_v2(Some(seed));
                xrc.update_cipher(key.as_bytes(), seed).unwrap_or(());
                unsafe { xrc.get_cipher().align_to().1.to_vec() }
            }
        }
    }

    pub fn encrypt_vec(&self, buf: Vec<u8>) -> AppResult<Vec<u8>> {
        match self {
            Xrc::V1(xrc) => Ok(xrc.encrypt_vec(buf)),
            Xrc::V2(k) => {
                XORCryptor::encrypt_v2(k.as_bytes(), buf).map_err(|e| AppError::XrcError(e))
            }
        }
    }

    pub fn decrypt_vec(&self, buf: Vec<u8>) -> AppResult<Vec<u8>> {
        match self {
            Xrc::V1(xrc) => Ok(xrc.decrypt_vec(buf)),
            Xrc::V2(k) => {
                XORCryptor::decrypt_v2(k.as_bytes(), buf).map_err(|e| AppError::XrcError(e))
            }
        }
    }

    fn compute_spice_seed(&self, file_path: &path::PathBuf) -> usize {
        match file_path.to_str() {
            Some(path) => {
                let mut seed = 1usize;
                for c in path
                    .chars()
                    .into_iter()
                    .map(|c| c as usize)
                    .filter(|c| c > &0)
                {
                    seed *= c;
                }
                seed
            }
            None => unreachable!("Should not have reached un-convertable pathbuf to str"),
        }
    }
}
