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

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    //Parse command-line arguments
    let args: Vec<String> = env::args().collect();//grab args

    //check amount
    if args.len() < 2 {
        println!("Usage: {} hostname", args[0]);
        return Ok(());
    }
    let hostname = args[1].clone();
    println!("Querying hostname: \"{}\"...", args[1]);

    //default dns resolver
    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

    //create custom resolver synced to our server
    //let mut resolver = Resolver::
    
    //IPv4 lookup
    let response = resolver.lookup_ip(hostname).await?;

    println!("IP addresses for {}:", args[1]);
    for ip in response {
        println!("{}", ip);
    }

    Ok(())
}