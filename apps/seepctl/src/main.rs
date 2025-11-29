use anyhow::Result;
use clap::{Parser, Subcommand};
use seep_config::SeepConfig;

#[derive(Parser)]
#[command(author, version, about = "Seep 控制台", propagate_version = true)]
struct Cli {
    #[arg(short, long, default_value = "config/seep.yaml")]
    config: String,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// 校验配置文件
    Check,
    /// 打印配置摘要
    Show,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Check => {
            SeepConfig::load_from_path(&cli.config)?;
            println!("配置有效");
        }
        Command::Show => {
            let config = SeepConfig::load_from_path(&cli.config)?;
            println!("控制平面监听: {}", config.control.api_bind);
            println!("入口数量: {}", config.ingress.len());
            println!("出口数量: {}", config.egress.len());
        }
    }
    Ok(())
}
