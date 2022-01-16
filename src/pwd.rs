use crate::alphabet::Alphabets;

pub type MasterKey = String;

pub struct PasswordSource<'a> {
    username: String,
    domain: String,
    alphabets: Alphabets<'a>,
}

pub struct DeterministicPwdGen {

}

impl DeterministicPwdGen {
    pub fn gen(&self, source: &PasswordSource){
        
    }
}