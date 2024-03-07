mod cli;

use app::AppConfig;
use clap::Parser;

fn main() {
    let args = Args::parse();

    let app_config = AppConfig::default();

    match args {
        Args {
            delete: false,
            find: false,
            list: false,
            new: true,
        } => app::create_credential(&app_config),
        Args {
            delete: false,
            find: false,
            list: true,
            new: false,
        } => app::list_credential(&app_config),
        Args {
            delete: false,
            find: true,
            list: false,
            new: false,
        } => app::find_credential(&app_config),
        Args {
            delete: true,
            find: false,
            list: false,
            new: false,
        } => app::delete_credential(&app_config),
        _ => todo!("not found"),
    }
}

mod app {
    use std::{borrow::Borrow, process::exit};

    use age::secrecy::{Secret, SecretString};
    use cuid2::cuid;

    use crate::{
        cli,
        safe_box::{Credential, DatabaseDisk},
    };

    pub struct AppConfig {
        database_location: String,
    }

    impl AppConfig {
        pub fn default() -> AppConfig {
            AppConfig {
                database_location: "./db-pass".to_string(),
            }
        }
    }

    pub fn prompt_secret() -> Secret<String> {
        let passphrase = cli::read_input_hidden("Passphrase > ");
        SecretString::new(passphrase)
    }

    pub fn create_credential(app_config: &AppConfig) {
        let secret = prompt_secret();

        let db_disk = DatabaseDisk::open(secret, &app_config.database_location);

        let label_input = cli::read_input("Label > ");
        let email_input = cli::read_input("Email > ");
        let password_input = cli::read_input_hidden("Password > ");

        let cred = Credential {
            id: cuid(),
            label: label_input,
            username: email_input,
            password: password_input,
        };
        db_disk.database.credentials.borrow_mut().push(cred);
        db_disk.close_with_encrypt();
    }

    // Somehow this broke the encryption file.
    pub fn delete_credential(app_config: &AppConfig) {
        let secret = prompt_secret();
        let db_disk = DatabaseDisk::open(secret, &app_config.database_location);

        let id_input = cli::read_input("Insert Id > ");

        let db = db_disk.database.borrow();
        let mut list_credential = db.credentials.borrow_mut();
        let _ = list_credential.iter_mut().filter(|x| x.id == id_input);

        let selected_index = list_credential.iter().position(|x| *x.id == id_input);
        match selected_index {
            Some(selected) => {
                list_credential.remove(selected);
            }
            None => {
                println!("Credential Not found");
                exit(2);
            }
        }
        drop(list_credential);

        db_disk.close_with_encrypt();
    }
    pub fn find_credential(app_config: &AppConfig) {
        let secret = prompt_secret();
        let db_disk = DatabaseDisk::open(secret, &app_config.database_location);

        let label_input = cli::read_input("Search Label > ");

        let db = db_disk.database.borrow();
        let mut list_credential = db.credentials.borrow();
        let mut list_selected = Vec::<Credential>::new();

        list_selected = list_credential
            .iter()
            .filter(|x| x.label.contains(&label_input))
            .map(|x| x.clone())
            .collect();

        if list_selected.len() < 1 {
            println!("Not found");
            exit(2);
        }

        print_creds(&list_selected);
    }

    pub fn list_credential(app_config: &AppConfig) {
        let secret = prompt_secret();
        let db_disk = DatabaseDisk::open(secret, &app_config.database_location);
        let db = db_disk.database.borrow();
        let list_credential = db.credentials.borrow();

        print_creds(&list_credential);
    }

    fn print_creds(creds: &Vec<Credential>) {
        println!(
            "| {: <10} | {: <10} | {: <10} | {: <10}",
            "Id", "Label", "Username", "Password"
        );
        for cred in creds.iter() {
            println!(
                "| {: <10} | {: <10} | {: <10} | {: <10}",
                cred.id, cred.label, cred.username, cred.password
            );
        }
    }
}

mod safe_box {
    use std::{
        borrow::Borrow,
        cell::RefCell,
        fs::{File, OpenOptions},
        io::{Read, Write},
        os::unix::fs::FileExt,
        process::exit,
        time::Instant,
    };

    use age::secrecy::Secret;
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, Debug, Clone)]
    pub struct Database {
        pub credentials: RefCell<Vec<Credential>>,
    }

    // Since serde_json (maybe) not support RefCell, we need to convert it manually
    #[derive(Serialize, Deserialize, Debug)]
    pub struct DatabaseJson {
        pub credentials: Vec<Credential>,
    }

    pub struct DatabaseDisk {
        pub secret: Secret<String>,
        pub location: String,
        pub file: RefCell<File>,
        pub database: Database,
    }

    impl DatabaseDisk {
        pub fn read_disk(location: &str) -> Result<(Vec<u8>, File), std::io::Error> {
            let f = OpenOptions::new().read(true).write(true).open(location);

            match f {
                Ok(mut file) => {
                    let mut buffer = Vec::new();

                    file.read_to_end(&mut buffer)?;

                    Ok((buffer, file))
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => {
                    let file = File::create(location)?;
                    Ok((vec![], file))
                }
                Err(e) => {
                    println!("Failed load file");
                    println!("{:?}", e);
                    exit(2);
                }
            }
        }

        pub fn open(secret: Secret<String>, location: &str) -> DatabaseDisk {
            let now = Instant::now();
            let (raw_data, file) = DatabaseDisk::read_disk(location).unwrap();
            println!("elapsed time to open : {:.2?}", now.elapsed());

            let now = Instant::now();
            let database = if raw_data.len() > 0 {
                Database::decrypt(&secret, &raw_data).unwrap()
            } else {
                Database {
                    credentials: RefCell::new(vec![]),
                }
            };
            println!("elapsed time to decrypt : {:.2?}", now.elapsed());

            DatabaseDisk {
                secret,
                location: location.to_string(),
                file: RefCell::new(file),
                database,
            }
        }

        pub fn close_with_encrypt(&self) {
            let encrypted = self.database.encrypt(self.secret.borrow().clone()).unwrap();
            self.file.borrow_mut().write_all_at(&encrypted, 0).unwrap();
        }
    }

    impl Database {
        pub fn to_json(self: &Self) -> DatabaseJson {
            DatabaseJson {
                credentials: self.credentials.borrow().clone(),
            }
        }

        pub fn from_json(db_json: DatabaseJson) -> Database {
            Database {
                credentials: RefCell::new(db_json.credentials),
            }
        }

        pub fn encrypt(&self, secret: Secret<String>) -> Result<Vec<u8>, SecureErr> {
            let encryptor = age::Encryptor::with_user_passphrase(secret);

            let vec_data = serde_json::ser::to_vec(&self.to_json())
                .map_err(|_| SecureErr::FailedEncrypt)
                .unwrap();

            let mut encrypted = vec![];
            let mut writer = encryptor
                .wrap_output(&mut encrypted)
                .map_err(|_| SecureErr::FailedEncrypt)
                .unwrap();
            writer
                .write_all(&vec_data)
                .map_err(|_| SecureErr::FailedEncrypt)
                .unwrap();
            writer
                .finish()
                .map_err(|_| SecureErr::FailedEncrypt)
                .unwrap();

            Ok(encrypted)
        }

        pub fn decrypt(secret: &Secret<String>, raw_data: &[u8]) -> Result<Database, SecureErr> {
            let decryptor =
                match age::Decryptor::new(raw_data).map_err(|_| SecureErr::FailedEncrypt)? {
                    age::Decryptor::Passphrase(d) => d,
                    _ => return Err(SecureErr::FailedEncrypt),
                };

            let mut decrypted = vec![];
            let mut reader = decryptor
                .decrypt(secret, None)
                .map_err(|_| SecureErr::FailedDecrypt)
                .unwrap();
            reader
                .read_to_end(&mut decrypted)
                .map_err(|_| SecureErr::FailedDecrypt)
                .unwrap();

            let result: DatabaseJson = serde_json::from_slice(&decrypted).unwrap();

            Ok(Database::from_json(result))
        }
    }

    #[derive(Serialize, Deserialize, Debug, Clone)]
    pub struct Credential {
        pub id: String,
        pub label: String,
        pub username: String,
        pub password: String,
    }

    #[derive(Debug)]
    pub enum SecureErr {
        FailedEncrypt,
        FailedDecrypt,
    }
}

#[derive(Parser, Debug)]
#[command(name = "Password Manager")]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long, action = clap::ArgAction::SetTrue)]
    new: bool,

    #[arg(short, long, action = clap::ArgAction::SetTrue)]
    find: bool,

    #[arg(short, long, action = clap::ArgAction::SetTrue)]
    delete: bool,

    #[arg(short, long, action = clap::ArgAction::SetTrue)]
    list: bool,
}
