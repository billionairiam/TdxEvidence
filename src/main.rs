mod report;

use report::TdTransportType;

use scroll::Pread;

fn main() {
    let report_data: [u8; 4] = [81, 0, 0, 0];
    match report_data.pread_with::<TdTransportType>(0, scroll::LE) {
        Ok(header) => {
            println!("Parsed header in main.rs:");
            println!("  Type: {}", header.type_);
            println!("  SubType: {}", header.sub_type);
            println!("  Version: {}", header.version);
            println!("  Reserved: {}", header.reserved);

            // 使用 Debug trait 打印整个结构体 (如果 derive 了 Debug)

            // 如果你导入了 report 模块中的函数，也可以调用它
            // report::process_report_header(&header);
            // 或者如果 use report::process_report_header;
            // process_report_header(&header);
        }
        Err(e) => {
            eprintln!("Failed to parse TdTransportType header in main: {:?}", e);
        }
    }
}
