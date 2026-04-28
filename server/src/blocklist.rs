use std::collections::HashSet;
use std::fs;

pub struct Blocklist {
    domains: HashSet<String>,
}

impl Blocklist {
    //construct and return Blocklist on load
    pub fn load(path: &str) -> Self {
        let mut domains = HashSet::new();
        let content = match fs::read_to_string(&path) {
            Ok(content) => content,
            Err(e) => {
                eprintln!("Blocklist failed to load at {} because of {}", path, e);
                return Self { domains };
            }
        };

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue; //skip weird lines
            }
            let pairs: Vec<&str> = line.split_whitespace().collect();
            //currently not parsing unpaired lines
            if pairs.len() >= 2 {
                let ip = pairs[0];
                let domain = pairs[1].to_lowercase();

                //skip hosts non-blocked custom entries, will be separate from blocklist
                if ip == "0.0.0.0"{
                    domains.insert(domain);
                }
            }
        }
        println!("Blocklist loaded {} domains", domains.len() );
        Self { domains }
    }

    pub fn is_blocked(&self, domain: &str) -> bool {
        //normalize domains with weird endings
        let domain = domain.trim_end_matches('.').to_lowercase();
        self.domains.contains(&domain)
    }

    //edit blocklist?
    //if we want to update the blocklist as the server is running this impl will have to change
    //might be able to add, but only load on restart
}