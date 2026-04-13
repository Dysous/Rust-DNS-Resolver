use std::env;
use std::error::Error;
use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::config::*;
use hickory_resolver::Resolver;
use hickory_resolver::name_server::TokioConnectionProvider;

//Client should be able to query our AWS dns server or any dns server
//this is a test client and not a huge part of our project except to demonstrate dns requests not over HTTP
//so we will be using crates that implement dns for us here
//these crates SHOULD NOT be used in other packages


//details needed to return
//(hostname, IP)
//RTT
//DNSSEC signature?

//usage: client [hostname]

fn usage() {
    println!("Usage (default resolver): dnsclient [-d] hostname");
    println!("Usage (custom resolver): dnsclient [-c] hostname");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    //Parse command-line arguments
    let args: Vec<String> = env::args().collect();//grab args

    //check amount
    if args.len() < 3 {
        eprintln!("Error: Missing arguments.");
        usage();
        return Err("Not enough arguments".into());
    }
    //check flags
    if args[1] != "-d" && args[1] != "-c" {
        eprintln!("Error: Invalid flag '{}'. Use -d or -c.", args[1]);
        usage();
        return Err("Invalid flag".into());
    }

    let hostname = args[2].clone();
    println!("Querying hostname: \"{}\"...", args[2]);

    let resolver = if args[1] == "-d" {//default dns resolver
        TokioAsyncResolver::tokio(
            ResolverConfig::default(),
            ResolverOpts::default(),
        )
    }
    else if args[1] == "-c" {//create custom resolver synced to our server
        let mut config = ResolverConfig::new();
        config.add_name_server(NameServerConfig {
            socket_addr: "54.83.56.34:2053".parse()?,//our AWS EC2 instance
            protocol: Protocol::Udp,
            tls_dns_name: None,
            trust_negative_responses: false,//won't cache if domain not found
            bind_addr: None,
        });

        TokioAsyncResolver::tokio(config, ResolverOpts::default())
    } else {
        eprintln!("Error: Invalid flag '{}'", args[1]);
        usage();
        return Err("Invalid flag".into());
    };

    //IPv4 lookup
    let response = resolver.lookup_ip(hostname).await?;

    println!("IP addresses for {}:", args[2]);
    for ip in response {
        println!("{}", ip);
    }

    Ok(())
}
