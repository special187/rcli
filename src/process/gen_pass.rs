use rand::seq::SliceRandom;
const UPPER: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ";
const LOWER: &[u8] = b"abcdefghijkmnopqrstuvwxyz";
const NUMBER: &[u8] = b"123456789";
const SYMBOL: &[u8] = b"!@#$%^&*_";
pub fn process_genpass(
    length: u8,
    upper: bool,
    lower: bool,
    number: bool,
    symbol: bool,
) -> anyhow::Result<()> {
    let mut rng = rand::thread_rng();
    let mut password = Vec::new();
    let mut chars = Vec::new();

    if upper {
        chars.extend_from_slice(UPPER);
        password.push(*UPPER.choose(&mut rng).expect("UPPER won't be empty"));
    }
    if lower {
        chars.extend_from_slice(LOWER);
        password.push(*LOWER.choose(&mut rng).expect("LOWER won't be empty"));
    }
    if number {
        chars.extend_from_slice(NUMBER);
        password.push(*NUMBER.choose(&mut rng).expect("NUMBER won't be empty"));
    }
    if symbol {
        chars.extend_from_slice(SYMBOL);
        password.push(*SYMBOL.choose(&mut rng).expect("SYMBOL won't be empty"));
    }

    if password.len() as u8 > length {
        anyhow::bail!("password length is too short")
    }

    if chars.is_empty() {
        anyhow::bail!("must specify at least one type of [uppercase lowercase number symbol]")
    }

    for _ in 0..(length - password.len() as u8) {
        password.push(*chars.choose(&mut rng).expect("chars won't be empty"));
    }

    password.shuffle(&mut rng);

    let password = String::from_utf8(password)?;
    println!("{}", password);

    let estimate = zxcvbn::zxcvbn(&password, &[])?;
    eprintln!("Password strength: {}", estimate.score());
    Ok(())
}
