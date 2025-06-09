use aael::Attester; 
use aael::tdx::TdxAttester;


#[tokio::main]
async fn main() {
    let attester = TdxAttester::default();
    let report_data: Vec<u8> = vec![0; 48];
    let evidence = attester.get_evidence(report_data).await;
    
    match evidence {
        Ok(evi) => {
            println!("evidence: {}", evi);
        },
        Err(e) => {
            eprintln!("get evidence error: {}", e);
        }
    }
}
