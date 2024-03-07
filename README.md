# Rust Password Manager

This is Password manager PoC using Rust.

## How to run

```sh
> cargo run -- --help

Usage: rust-pass-manager [OPTIONS]

Options:
  -n, --new      
  -f, --find     
  -d, --delete   
  -l, --list     
  -h, --help     Print help
  -V, --version  Print version
```

## How it works

It will create new database using binary data that encrypted using [age encryption](https://github.com/FiloSottile/age)
