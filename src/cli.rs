//! Общие clap-интерфейсы всех исполняемых файлов.

use crate::config;
use clap::{Args, CommandFactory as _, Parser};
use std::{
    error::Error,
    path::{Path, PathBuf},
};

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
    pub genconf: Option<PathBuf>,

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

/// Версия upstream-реализации, с которой сверяется протокол.
pub const UPSTREAM_YGGDRASIL_GO_VERSION: &str = "0.5.15";
/// Коммит `yggdrasil-go`, на который ориентирован этот код.
pub const UPSTREAM_YGGDRASIL_GO_COMMIT: &str = "2c7f050";
/// Коммит `ironwood`, на который ориентирован этот код.
pub const UPSTREAM_IRONWOOD_COMMIT: &str = "0712ecc";

const COMPATIBILITY_HELP: &str = "\
Upstream compatibility:
  yggdrasil-go 0.5.15 (2c7f050)
  ironwood 0712ecc
  wire protocol 0.5";

/// Главный CLI.
#[derive(Debug, Parser)]
#[command(
    name = "uu-yggdrasil",
    version,
    long_about = None,
    after_help = COMPATIBILITY_HELP
)]
pub struct ArgsYgg {
    /// TOML/JSON-конфиг.
    #[arg(
        short = 'c',
        long = "config",
        value_name = "FILE",
        default_value = "yggdrasil.toml"
    )]
    pub config: Option<PathBuf>,

    #[command(flatten)]
    pub generate: GenConfArgs,
}

/// Точка входа главного CLI.
///
/// # Errors
/// Ошибка генерации/записи конфига.
pub fn run() -> Result<(), Box<dyn Error>> {
    crate::init_tracing();
    let cli = ArgsYgg::parse();
    if cli.generate.run()? {
        return Ok(());
    }

    ArgsYgg::command().print_help()?;
    println!();
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::cli::ArgsYgg;
    use clap::Parser;
    use std::path::{Path, PathBuf};

    #[test]
    fn genconf_without_path_uses_stdout_marker() {
        let cli = ArgsYgg::try_parse_from(["uu-yggdrasil", "-g"]).expect("parse");
        assert_eq!(cli.generate.genconf.as_deref(), Some(Path::new("-")));
    }

    #[test]
    fn genconf_is_available_in_every_binary() {
        let daemon = ArgsYgg::try_parse_from(["uu-yggdrasil-daemon", "-g"]).expect("parse");
        assert_eq!(daemon.generate.genconf.as_deref(), Some(Path::new("-")));

        let echo = ArgsYgg::try_parse_from(["uu-yggdrasil-echo", "-g"]).expect("parse");
        assert_eq!(echo.generate.genconf.as_deref(), Some(Path::new("-")));
    }

    #[test]
    fn daemon_config_has_default() {
        let cli = ArgsYgg::try_parse_from(["uu-yggdrasil-daemon"]).expect("parse");
        match cli.config {
            Some(path) => {
                assert_eq!(path, PathBuf::from("yggdrasil.toml"));
            }
            None => todo!(),
        }
    }
}
