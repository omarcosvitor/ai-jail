use crate::config::Config;

pub fn apply(_config: &Config, verbose: bool) {
    if verbose {
        crate::output::verbose(
            "Resource limits: managed by the Windows MXC Job Object",
        );
    }
}
