use std::io;
use std::error::Error;
use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::config::*;

//Client should be able to query our AWS dns server or any dns server
//this is a test client and not a huge part of our project except to demonstrate dns requests not over HTTP
//so we will be using crates that implement dns for us here
//these crates SHOULD NOT be used in other packages

//usage: client [d/c] [hostname]

fn usage() {
    println!("Usage (default resolver): d hostname");
    println!("Usage (custom resolver): c hostname");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    //main loop waiting for input
    loop{
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let input = input.trim();

        if input == "exit" {
            break;
        }
        if input.is_empty() {
            continue;
        }

        handle_input(input).await?;
    }
    Ok(())
}


async fn handle_input (input: &str) -> Result <(), Box<dyn Error>> {
    //Parse command-line arguments
    let args: Vec<&str> = input.split_whitespace().collect();
    let mut correct_args:bool  = true;

    //check amount
    if args.len() < 2 {
        println!("Error: Missing arguments.");
        usage();
        correct_args = false;
    }
    //check flags
    if args.len() > 1 && args[0] != "d" && args[0] != "c" {
        println!("Error: Invalid flag '{}'. Use d or c.", args[0]);
        usage();
        correct_args = false;
    }

    if correct_args {
        let hostname = args[1];
        println!("Querying hostname: \"{}\"...", args[1]);

        let resolver = if args[0] == "d" {//default dns resolver
            TokioAsyncResolver::tokio(
                ResolverConfig::default(),
                ResolverOpts::default(),
            )
        }
        else if args[0] == "c" {//create custom resolver synced to our server
            let mut config = ResolverConfig::new();
            config.add_name_server(NameServerConfig {
                socket_addr: "54.83.56.34:53".parse()?,//our AWS EC2 instance
                protocol: Protocol::Udp,
                tls_dns_name: None,
                trust_negative_responses: false,//won't cache if domain not found
                bind_addr: None,
            });

            //verifies data is sent from server
            let mut opts = ResolverOpts::default();
            opts.validate = true;

            TokioAsyncResolver::tokio(config, opts)
        } else {
            eprintln!("Error: Invalid flag '{}'", args[0]);
            usage();
            return Err("Invalid flag".into());
        };


        match resolver.lookup_ip(hostname).await {
            Ok(responses) => {
                println!("DNSSEC: Verified");
                println!("Hostname: \"{}\"", hostname.trim());
                for ip in responses {
                    println!("{}", ip);
                }
            }
            Err(e) => {
                println!("DNSSEC: Error: {}", e);
            }
        }
    }

   Ok(())
}