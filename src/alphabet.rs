pub struct Alphabets<'a>(&'a[u8]);

pub enum AlphabetsType<'a> {
    Lowers,
    Uppers,
    Numbers,
    BasicSymbols,
    MoreSymbols,
    Custom(&'a[u8]),
}

fn from_type(atype: AlphabetsType) -> Alphabets {
    let alphabet = match atype {
        AlphabetsType::Lowers => "abcdefghijklmnopqrstuvwxyz".as_bytes(),
        AlphabetsType::Uppers => "ABCDEFGHIJKLMNOPQRSTUVWXYZ".as_bytes(),
        AlphabetsType::Numbers => "0123456789".as_bytes(),
        AlphabetsType::BasicSymbols => "!@$&=_?".as_bytes(),
        AlphabetsType::MoreSymbols => "#$%^*()-+<>,./;:'\"[]{}|".as_bytes(),
        AlphabetsType::Custom(customs) => customs,
    };

    Alphabets(alphabet)
}

impl<'a> Alphabets<'a> {
    pub fn new(alphabets: &[AlphabetsType]) -> Alphabets<'a> {
        Alphabets()
    }
}