//! Общие clap-интерфейсы всех исполняемых файлов.

use std::{error::Error, path::Path};

use clap::{Args, CommandFactory as _, Parser};

use crate::config;

/// Общие аргументы генерации конфига.
#[derive(Debug, Args)]
pub struct GenConfArgs {
    /// Сгенерировать новый конфиг (без FILE — в stdout).
    #[arg(
        short = 'g',
        long = "genconf",
        value_name = "FILE",
        num_args = 0..=1,
        default_missing_value = "-"
    )]
    pub genconf: Option<std::path::PathBuf>,

    /// Не перезаписывать существующий файл при --genconf FILE.
    #[arg(short = 'n', long = "no-replace")]
    pub no_replace: bool,
}

impl GenConfArgs {
    /// Выполнить генерацию, если запрошен `-g`/`--genconf`.
    ///
    /// Возвращает `true`, если работа завершена и запускать узел не нужно.
    ///
    /// # Errors
    /// Ошибка генерации/записи конфига.
    pub fn run(&self) -> Result<bool, Box<dyn Error>> {
        let Some(path) = self.genconf.as_deref() else {
            return Ok(false);
        };
        let path = (path != Path::new("-")).then_some(path);
        config::generate_to(path, self.no_replace)?;
        Ok(true)
    }
}

/// Главный CLI.
#[derive(Debug, Parser)]
#[command(
    name = "uu-yggdrasil",
    version,
    about = "uu-yggdrasil node",
    long_about = None
)]
pub struct Cli {
    #[command(flatten)]
    pub generate: GenConfArgs,
}

/// Аргументы демона.
#[derive(Debug, Parser)]
#[command(name = "uu-yggdrasil-daemon", version, about = "uu-yggdrasil daemon")]
pub struct DaemonCli {
    /// TOML/JSON-конфиг.
    #[arg(
        short = 'c',
        long = "config",
        value_name = "FILE",
        default_value = "yggdrasil.toml"
    )]
    pub config: std::path::PathBuf,

    /// Не создавать TUN, даже если он включён в конфиге.
    #[arg(long = "no-tun")]
    pub no_tun: bool,

    #[command(flatten)]
    pub generate: GenConfArgs,
}

/// Аргументы echo-узла.
#[derive(Debug, Parser)]
#[command(
    name = "uu-yggdrasil-echo",
    version,
    about = "uu-yggdrasil no-TUN echo node"
)]
pub struct EchoCli {
    /// TOML/JSON-конфиг (необязательно).
    #[arg(short = 'c', long = "config", value_name = "FILE")]
    pub config: Option<std::path::PathBuf>,

    #[command(flatten)]
    pub generate: GenConfArgs,
}

/// Точка входа главного CLI.
///
/// # Errors
/// Ошибка генерации/записи конфига.
pub fn run() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();
    if cli.generate.run()? {
        return Ok(());
    }

    Cli::command().print_help()?;
    println!();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genconf_without_path_uses_stdout_marker() {
        let cli = Cli::try_parse_from(["uu-yggdrasil", "-g"]).expect("parse");
        assert_eq!(cli.generate.genconf.as_deref(), Some(Path::new("-")));
    }

    #[test]
    fn genconf_is_available_in_every_binary() {
        let daemon = DaemonCli::try_parse_from(["uu-yggdrasil-daemon", "-g"]).expect("parse");
        assert_eq!(daemon.generate.genconf.as_deref(), Some(Path::new("-")));

        let echo = EchoCli::try_parse_from(["uu-yggdrasil-echo", "-g"]).expect("parse");
        assert_eq!(echo.generate.genconf.as_deref(), Some(Path::new("-")));
    }

    #[test]
    fn daemon_config_has_default() {
        let cli = DaemonCli::try_parse_from(["uu-yggdrasil-daemon"]).expect("parse");
        assert_eq!(cli.config, std::path::PathBuf::from("yggdrasil.toml"));
    }
}
