use aes_gcm::{
    aead::Nonce as AesNonce,
    aead::{Aead, KeyInit},
    Aes256Gcm,
};
use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Argon2, PasswordHasher,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use thiserror::Error;
use walkdir::WalkDir;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Encryption error: {0}")]
    Encryption(String),
    #[error("Decryption error: {0}")]
    Decryption(String),
    #[error("Password error: {0}")]
    Password(String),
    #[error("WalkDir error: {0}")]
    WalkDir(#[from] walkdir::Error),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

#[derive(Serialize, Deserialize)]
struct FileMetadata {
    original_name: String,
    is_dir: bool,
    files: Vec<EncryptedFile>,
}

#[derive(Serialize, Deserialize)]
struct EncryptedFile {
    relative_path: String,
    content_size: u64,
}

pub fn encrypt_path(path: &Path, password: &str) -> Result<PathBuf, CryptoError> {
    let salt = SaltString::generate(&mut OsRng);
    let salt_str = salt.as_str();
    let salt_base64 = BASE64.encode(salt_str);

    let argon2 = Argon2::default();
    let key = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| CryptoError::Password(e.to_string()))?
        .hash
        .ok_or_else(|| CryptoError::Password("Failed to generate key".to_string()))?
        .as_bytes()
        .to_vec();

    let cipher =
        Aes256Gcm::new_from_slice(&key).map_err(|e| CryptoError::Encryption(e.to_string()))?;

    let nonce_bytes: [u8; 12] = rand::random();
    let nonce = AesNonce::<Aes256Gcm>::from_slice(&nonce_bytes);

    let encrypted_path = if path.is_file() {
        let mut file = File::open(path)?;
        let mut contents = Vec::new();
        file.read_to_end(&mut contents)?;

        // Create metadata for single file
        let metadata = FileMetadata {
            original_name: path
                .file_name()
                .ok_or_else(|| CryptoError::Encryption("Invalid file name".to_string()))?
                .to_string_lossy()
                .into_owned(),
            is_dir: false,
            files: vec![],
        };

        // Encrypt file contents
        let encrypted_contents = cipher
            .encrypt(nonce, contents.as_ref())
            .map_err(|e| CryptoError::Encryption(e.to_string()))?;

        // Encrypt metadata
        let metadata_json = serde_json::to_string(&metadata)?;
        let encrypted_metadata = cipher
            .encrypt(nonce, metadata_json.as_bytes())
            .map_err(|e| CryptoError::Encryption(e.to_string()))?;

        let parent = path.parent().unwrap_or_else(|| Path::new(""));
        let encrypted_file_path = parent.join(format!("{}.encrypted", rand::random::<u64>()));

        let mut encrypted_file = File::create(&encrypted_file_path)?;

        // Write header
        encrypted_file.write_all(salt_base64.as_bytes())?;
        encrypted_file.write_all(b"\n")?;
        encrypted_file.write_all(&nonce_bytes)?;

        // Write metadata
        let metadata_len = encrypted_metadata.len() as u32;
        encrypted_file.write_all(&metadata_len.to_le_bytes())?;
        encrypted_file.write_all(&encrypted_metadata)?;

        // Write content
        encrypted_file.write_all(&encrypted_contents)?;

        encrypted_file_path
    } else {
        // For directory, collect all files first
        let mut files = Vec::new();
        let mut all_contents = Vec::new();

        for entry in WalkDir::new(path) {
            let entry = entry?;
            if entry.file_type().is_file() {
                let relative_path = entry
                    .path()
                    .strip_prefix(path)
                    .map_err(|e| CryptoError::Encryption(e.to_string()))?
                    .to_string_lossy()
                    .into_owned();

                let mut file = File::open(entry.path())?;
                let mut contents = Vec::new();
                file.read_to_end(&mut contents)?;

                let encrypted_contents = cipher
                    .encrypt(nonce, contents.as_ref())
                    .map_err(|e| CryptoError::Encryption(e.to_string()))?;

                files.push(EncryptedFile {
                    relative_path,
                    content_size: encrypted_contents.len() as u64,
                });

                all_contents.extend(encrypted_contents);
            }
        }

        // Create metadata for directory
        let metadata = FileMetadata {
            original_name: path
                .file_name()
                .ok_or_else(|| CryptoError::Encryption("Invalid directory name".to_string()))?
                .to_string_lossy()
                .into_owned(),
            is_dir: true,
            files,
        };

        // Encrypt metadata
        let metadata_json = serde_json::to_string(&metadata)?;
        let encrypted_metadata = cipher
            .encrypt(nonce, metadata_json.as_bytes())
            .map_err(|e| CryptoError::Encryption(e.to_string()))?;

        let parent = path.parent().unwrap_or_else(|| Path::new(""));
        let encrypted_file_path = parent.join(format!("{}.encrypted", rand::random::<u64>()));

        let mut encrypted_file = File::create(&encrypted_file_path)?;

        // Write header
        encrypted_file.write_all(salt_base64.as_bytes())?;
        encrypted_file.write_all(b"\n")?;
        encrypted_file.write_all(&nonce_bytes)?;

        // Write metadata
        let metadata_len = encrypted_metadata.len() as u32;
        encrypted_file.write_all(&metadata_len.to_le_bytes())?;
        encrypted_file.write_all(&encrypted_metadata)?;

        // Write all contents
        encrypted_file.write_all(&all_contents)?;

        encrypted_file_path
    };

    Ok(encrypted_path)
}

pub fn decrypt_path(encrypted_path: &Path, password: &str) -> Result<PathBuf, CryptoError> {
    if !encrypted_path.exists() {
        return Err(CryptoError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "Encrypted path does not exist",
        )));
    }

    let file = File::open(encrypted_path)?;
    let mut reader = BufReader::new(file);

    // Read salt and nonce
    let mut salt_line = String::new();
    reader.read_line(&mut salt_line)?;
    let salt_base64 = salt_line.trim().to_string();

    let mut nonce_bytes = [0u8; 12];
    reader.read_exact(&mut nonce_bytes)?;

    let salt_str = BASE64
        .decode(salt_base64)
        .map_err(|e| CryptoError::Password(e.to_string()))?;
    let salt_str = String::from_utf8(salt_str).map_err(|e| CryptoError::Password(e.to_string()))?;
    let salt = SaltString::from_b64(&salt_str).map_err(|e| CryptoError::Password(e.to_string()))?;

    let argon2 = Argon2::default();
    let key = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| CryptoError::Password(e.to_string()))?
        .hash
        .ok_or_else(|| CryptoError::Password("Failed to generate key".to_string()))?
        .as_bytes()
        .to_vec();

    let cipher =
        Aes256Gcm::new_from_slice(&key).map_err(|e| CryptoError::Decryption(e.to_string()))?;

    let nonce = AesNonce::<Aes256Gcm>::from_slice(&nonce_bytes);

    // Read and decrypt metadata
    let mut metadata_len_bytes = [0u8; 4];
    reader.read_exact(&mut metadata_len_bytes)?;
    let metadata_len = u32::from_le_bytes(metadata_len_bytes) as usize;

    let mut encrypted_metadata = vec![0u8; metadata_len];
    reader.read_exact(&mut encrypted_metadata)?;

    let metadata_json = cipher
        .decrypt(nonce, encrypted_metadata.as_ref())
        .map_err(|e| CryptoError::Decryption(e.to_string()))?;

    let metadata: FileMetadata = serde_json::from_slice(&metadata_json)?;

    let parent = encrypted_path.parent().unwrap_or_else(|| Path::new(""));

    if metadata.is_dir {
        // Create directory and decrypt all files
        let decrypted_dir = parent.join(&metadata.original_name);
        fs::create_dir_all(&decrypted_dir)?;

        for file_info in metadata.files {
            // Read and decrypt file contents
            let mut encrypted_contents = vec![0u8; file_info.content_size as usize];
            reader.read_exact(&mut encrypted_contents)?;

            let decrypted_contents = cipher
                .decrypt(nonce, encrypted_contents.as_ref())
                .map_err(|e| CryptoError::Decryption(e.to_string()))?;

            let file_path = decrypted_dir.join(&file_info.relative_path);
            if let Some(parent) = file_path.parent() {
                fs::create_dir_all(parent)?;
            }

            let mut decrypted_file = File::create(file_path)?;
            decrypted_file.write_all(&decrypted_contents)?;
        }

        Ok(decrypted_dir)
    } else {
        // Decrypt single file
        let mut encrypted_contents = Vec::new();
        reader.read_to_end(&mut encrypted_contents)?;

        let decrypted_contents = cipher
            .decrypt(nonce, encrypted_contents.as_ref())
            .map_err(|e| CryptoError::Decryption(e.to_string()))?;

        let decrypted_path = parent.join(&metadata.original_name);
        let mut decrypted_file = File::create(&decrypted_path)?;
        decrypted_file.write_all(&decrypted_contents)?;

        Ok(decrypted_path)
    }
}
