//! Zed extension: starts the Kashif language server (`vulnscan lsp --stdio`) found on the worktree's PATH.
//! Override the command in Zed's settings: "lsp": { "kashif": { "binary": { "path": "...", "arguments": [...] } } }.

use zed_extension_api::{self as zed, settings::LspSettings, LanguageServerId, Result};

struct Kashif;

impl zed::Extension for Kashif {
    fn new() -> Self {
        Kashif
    }

    fn language_server_command(&mut self, id: &LanguageServerId, worktree: &zed::Worktree) -> Result<zed::Command> {
        let binary = LspSettings::for_worktree(id.as_ref(), worktree).ok().and_then(|s| s.binary);
        if let Some(path) = binary.as_ref().and_then(|b| b.path.clone()) {
            let args = binary
                .and_then(|b| b.arguments)
                .unwrap_or_else(|| vec!["lsp".into(), "--stdio".into()]);
            return Ok(zed::Command { command: path, args, env: Default::default() });
        }
        let path = worktree.which("vulnscan").ok_or_else(|| {
            "vulnscan is not on PATH: pip install git+https://github.com/abdulrahmanahmedelabed-prog/vulnscan".to_string()
        })?;
        Ok(zed::Command { command: path, args: vec!["lsp".into(), "--stdio".into()], env: Default::default() })
    }

    fn language_server_initialization_options(
        &mut self,
        id: &LanguageServerId,
        worktree: &zed::Worktree,
    ) -> Result<Option<zed::serde_json::Value>> {
        Ok(LspSettings::for_worktree(id.as_ref(), worktree).ok().and_then(|s| s.initialization_options))
    }

    fn language_server_workspace_configuration(
        &mut self,
        id: &LanguageServerId,
        worktree: &zed::Worktree,
    ) -> Result<Option<zed::serde_json::Value>> {
        Ok(LspSettings::for_worktree(id.as_ref(), worktree).ok().and_then(|s| s.settings))
    }
}

zed::register_extension!(Kashif);
