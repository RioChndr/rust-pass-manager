use std::io::{stdin, stdout, Write};

pub fn read_input(prefix: &str) -> String {
    let mut line = String::new();
    print!("{}", prefix);
    stdout().flush().unwrap();
    stdin()
        .read_line(&mut line)
        .expect("Error: Could not read a line");

    line.trim().to_string()
}

pub fn read_input_hidden(prefix: &str) -> String {
    rpassword::prompt_password(prefix).unwrap()
}
