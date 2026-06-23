use crate::bash::parse_shell_lc_plain_commands;
use std::path::Path;
#[cfg(windows)]
#[path = "windows_dangerous_commands.rs"]
mod windows_dangerous_commands;

pub fn command_might_be_dangerous(command: &[String]) -> bool {
    #[cfg(windows)]
    {
        if windows_dangerous_commands::is_dangerous_command_windows(command) {
            return true;
        }
    }

    if is_dangerous_to_call_with_exec(command) {
        return true;
    }

    // Support `bash -lc "<script>"` where the any part of the script might contain a dangerous command.
    if let Some(all_commands) = parse_shell_lc_plain_commands(command)
        && all_commands
            .iter()
            .any(|cmd| is_dangerous_to_call_with_exec(cmd))
    {
        return true;
    }

    false
}

/// Returns whether already-tokenized PowerShell words should be treated as
/// dangerous by the Windows unmatched-command heuristics.
pub fn is_dangerous_powershell_words(command: &[String]) -> bool {
    #[cfg(windows)]
    {
        windows_dangerous_commands::is_dangerous_powershell_words(command)
    }

    #[cfg(not(windows))]
    {
        let _ = command;
        false
    }
}

fn is_git_global_option_with_value(arg: &str) -> bool {
    matches!(
        arg,
        "-C" | "-c"
            | "--config-env"
            | "--exec-path"
            | "--git-dir"
            | "--namespace"
            | "--super-prefix"
            | "--work-tree"
    )
}

fn is_git_global_option_with_inline_value(arg: &str) -> bool {
    matches!(
        arg,
        s if s.starts_with("--config-env=")
            || s.starts_with("--exec-path=")
            || s.starts_with("--git-dir=")
            || s.starts_with("--namespace=")
            || s.starts_with("--super-prefix=")
            || s.starts_with("--work-tree=")
    ) || ((arg.starts_with("-C") || arg.starts_with("-c")) && arg.len() > 2)
}

pub(crate) fn executable_name_lookup_key(raw: &str) -> Option<String> {
    #[cfg(windows)]
    {
        Path::new(raw)
            .file_name()
            .and_then(|name| name.to_str())
            .map(|name| {
                let name = name.to_ascii_lowercase();
                for suffix in [".exe", ".cmd", ".bat", ".com"] {
                    if let Some(stripped) = name.strip_suffix(suffix) {
                        return stripped.to_string();
                    }
                }
                name
            })
    }

    #[cfg(not(windows))]
    {
        Path::new(raw)
            .file_name()
            .and_then(|name| name.to_str())
            .map(std::borrow::ToOwned::to_owned)
    }
}

/// Find the first matching git subcommand, skipping known global options that
/// may appear before it (e.g., `-C`, `-c`, `--git-dir`).
///
/// Shared with `is_safe_command` to avoid git-global-option bypasses.
pub(crate) fn find_git_subcommand<'a>(
    command: &'a [String],
    subcommands: &[&str],
) -> Option<(usize, &'a str)> {
    let cmd0 = command.first().map(String::as_str)?;
    if executable_name_lookup_key(cmd0).as_deref() != Some("git") {
        return None;
    }

    let mut skip_next = false;
    for (idx, arg) in command.iter().enumerate().skip(1) {
        if skip_next {
            skip_next = false;
            continue;
        }

        let arg = arg.as_str();

        if is_git_global_option_with_inline_value(arg) {
            continue;
        }

        if is_git_global_option_with_value(arg) {
            skip_next = true;
            continue;
        }

        if arg == "--" || arg.starts_with('-') {
            continue;
        }

        if subcommands.contains(&arg) {
            return Some((idx, arg));
        }

        // In git, the first non-option token is the subcommand. If it isn't
        // one of the subcommands we're looking for, we must stop scanning to
        // avoid misclassifying later positional args (e.g., branch names).
        return None;
    }

    None
}

fn is_dangerous_to_call_with_exec(command: &[String]) -> bool {
    let cmd0 = match command.first().map(String::as_str) {
        Some(cmd0) => cmd0,
        None => return false,
    };

    // Match on the executable's basename so that absolute/relative paths
    // (e.g. `/bin/rm`, `./rm`) are classified the same as the bare name. This
    // is a defensive widening: a privilege-/data-destroying command must not
    // slip past the backstop merely because it was invoked by path.
    let name = executable_name_lookup_key(cmd0);
    let rest = &command[1..];
    match name.as_deref() {
        // `sudo`/`doas` are transparent wrappers; skip their options (incl.
        // `-E`, `--`, and value-taking flags like `-u user`) before re-checking
        // the wrapped command, so `sudo -E rm -rf /` cannot slip past as root.
        Some("sudo" | "doas") => is_dangerous_to_call_with_exec(strip_sudo_prefix(rest)),

        // `env [VAR=val ...] <cmd>` is a transparent wrapper. Skip leading
        // assignments and `-`/`-i`/`-u VAR` style flags, then re-check the
        // underlying command so `env rm -rf /` is not treated as benign.
        Some("env") => is_dangerous_to_call_with_exec(strip_env_prefix(rest)),

        // `rm` with a force/recursive flag anywhere in the argument list. The
        // original heuristic only checked argv[1], so `rm /important -rf` and
        // `rm --force ...` previously read as safe.
        Some("rm") => rest.iter().any(|arg| is_rm_force_or_recursive_flag(arg)),

        // Raw block/character device writers. Writing to a device or building
        // a filesystem is unconditionally destructive and not something the
        // sandbox can undo, so always force human review.
        Some("dd") => rest.iter().any(|arg| arg.starts_with("of=")),
        Some("mkfs") => true,
        Some(name) if name.starts_with("mkfs.") => true,
        Some("fdisk" | "parted" | "sfdisk" | "wipefs" | "shred" | "blkdiscard") => true,

        // Disk/partition-table overwrite via `>`/`tee` is handled at the shell
        // layer; here we catch the direct tools that need no shell operator.

        // Recursive/forceful permission or ownership changes are a classic way
        // to brick a tree or escalate; require approval whenever recursion is
        // requested.
        Some("chmod" | "chown" | "chgrp") => rest.iter().any(|arg| is_recursive_flag(arg)),

        // History-rewriting / forced remote mutation. `git push --force`(-f)
        // and `git push --delete` can destroy others' work irreversibly and
        // are outside the sandbox's protection, so they warrant a prompt.
        Some("git") => is_dangerous_git_invocation(rest),

        // ── anything else ─────────────────────────────────────────────────
        _ => false,
    }
}

/// True for `rm` flags that imply force and/or recursion, including bundled
/// short flags such as `-rf`, `-fr`, `-Rf`, and the long forms.
fn is_rm_force_or_recursive_flag(arg: &str) -> bool {
    if arg == "--force" || arg == "--recursive" {
        return true;
    }
    // A bundled short-flag group like `-rf`. Treat it as dangerous if it
    // requests force or recursion; ignore non-flag operands and `--`.
    if let Some(flags) = arg.strip_prefix('-')
        && arg != "--"
        && !flags.is_empty()
        && !flags.starts_with('-')
    {
        return flags.chars().any(|c| c == 'f' || c == 'r' || c == 'R');
    }
    false
}

/// Skip leading `NAME=value` assignments and benign `env` flags so the wrapped
/// command can be re-examined. Conservative: any flag that takes a value we do
/// not understand stops the scan and yields the remaining tokens.
fn strip_env_prefix(args: &[String]) -> &[String] {
    let mut idx = 0;
    while idx < args.len() {
        let arg = args[idx].as_str();
        // `--` ends option processing; the command follows.
        if arg == "--" {
            idx += 1;
            break;
        }
        if arg == "-i"
            || arg == "--ignore-environment"
            || arg == "-"
            || arg == "-0"
            || arg == "--null"
        {
            idx += 1;
            continue;
        }
        // Options that consume a following value: `-u NAME`/`--unset NAME`
        // drop a variable, `-C DIR`/`--chdir DIR` change directory.
        if arg == "-u" || arg == "--unset" || arg == "-C" || arg == "--chdir" {
            idx += 2;
            continue;
        }
        // Long `--opt=value` forms such as `--unset=NAME` or `--chdir=DIR`.
        if arg.starts_with("--") && arg.contains('=') {
            idx += 1;
            continue;
        }
        // `VAR=value` assignment.
        if arg.contains('=') && !arg.starts_with('-') {
            idx += 1;
            continue;
        }
        break;
    }
    &args[idx.min(args.len())..]
}

/// Skip leading `sudo`/`doas` options and environment assignments so the
/// wrapped command can be re-examined. Mirrors [`strip_env_prefix`]: value-
/// taking options (`-u user`, `-g group`, `-C dir`, …) consume their argument,
/// `--` ends option processing, and any other `-`-prefixed token or `VAR=value`
/// assignment is skipped. Conservative — if the command cannot be located the
/// remaining tokens are returned unchanged.
fn strip_sudo_prefix(args: &[String]) -> &[String] {
    let mut idx = 0;
    while idx < args.len() {
        let arg = args[idx].as_str();
        if arg == "--" {
            idx += 1;
            break;
        }
        // Options that consume a following value.
        if matches!(
            arg,
            "-u" | "--user"
                | "-g"
                | "--group"
                | "-p"
                | "--prompt"
                | "-C"
                | "--close-from"
                | "-D"
                | "--chdir"
                | "-r"
                | "--role"
                | "-t"
                | "--type"
                | "-h"
                | "--host"
                | "-R"
                | "--chroot"
                | "-U"
                | "--other-user"
                | "-T"
                | "--command-timeout"
        ) {
            idx += 2;
            continue;
        }
        // `--opt=value` long options and any other standalone flag.
        if arg.starts_with('-') && arg != "-" {
            idx += 1;
            continue;
        }
        // `VAR=value` environment assignment accepted before the command.
        if arg.contains('=') {
            idx += 1;
            continue;
        }
        break;
    }
    &args[idx.min(args.len())..]
}

/// True for a recursive flag on `chmod`/`chown`/`chgrp`, including bundled
/// short-flag groups such as `-hR` or `-Rf` as well as the `--recursive` long
/// form. Only the capital `R` denotes recursion for these tools.
fn is_recursive_flag(arg: &str) -> bool {
    if arg == "--recursive" {
        return true;
    }
    if let Some(flags) = arg.strip_prefix('-')
        && arg != "--"
        && !flags.is_empty()
        && !flags.starts_with('-')
    {
        return flags.contains('R');
    }
    false
}

/// True for `git` subcommands that perform irreversible, outside-sandbox
/// mutations (forced/deleting pushes). Read-only and ordinary subcommands are
/// intentionally left to the normal approval flow.
fn is_dangerous_git_invocation(rest: &[String]) -> bool {
    // Reuse the shared global-option-aware subcommand finder so that
    // `git -C dir push --force` is not bypassed.
    let full: Vec<String> = std::iter::once("git".to_string())
        .chain(rest.iter().cloned())
        .collect();
    let Some((push_idx, _)) = find_git_subcommand(&full, &["push"]) else {
        return false;
    };
    full.iter().skip(push_idx + 1).any(|arg| {
        matches!(
            arg.as_str(),
            "-f" | "--force" | "--force-with-lease" | "--delete" | "-d" | "--mirror"
        ) || arg.starts_with("--force-with-lease=")
            || is_dangerous_push_refspec(arg)
    })
}

/// A push refspec is dangerous when it force-updates (leading `+`, e.g.
/// `+main` or `+refs/heads/main:...`) or deletes the remote ref (empty source,
/// i.e. a leading `:` such as `:old-branch`). Option tokens start with `-` and
/// are never refspecs, so they are excluded.
fn is_dangerous_push_refspec(arg: &str) -> bool {
    if arg.starts_with('-') {
        return false;
    }
    arg.starts_with('+') || arg.starts_with(':')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vec_str(items: &[&str]) -> Vec<String> {
        items.iter().map(std::string::ToString::to_string).collect()
    }

    #[test]
    fn rm_rf_is_dangerous() {
        assert!(command_might_be_dangerous(&vec_str(&["rm", "-rf", "/"])));
    }

    #[test]
    fn rm_f_is_dangerous() {
        assert!(command_might_be_dangerous(&vec_str(&["rm", "-f", "/"])));
    }

    #[test]
    fn rm_force_flag_after_operand_is_dangerous() {
        // The original argv[1]-only check missed flags placed after the path.
        assert!(command_might_be_dangerous(&vec_str(&[
            "rm",
            "/important",
            "-rf"
        ])));
        assert!(command_might_be_dangerous(&vec_str(&[
            "rm", "--force", "x"
        ])));
        assert!(command_might_be_dangerous(&vec_str(&["rm", "-fr", "x"])));
    }

    #[test]
    fn plain_rm_without_force_is_not_flagged() {
        // A bare `rm file` is destructive but reversible-ish and is left to the
        // normal approval/sandbox flow; only force/recursive forms are backstopped.
        assert!(!command_might_be_dangerous(&vec_str(&["rm", "file.txt"])));
    }

    #[test]
    fn rm_via_absolute_path_is_dangerous() {
        assert!(command_might_be_dangerous(&vec_str(&[
            "/bin/rm", "-rf", "/"
        ])));
    }

    #[test]
    fn sudo_and_env_wrappers_are_unwrapped() {
        assert!(command_might_be_dangerous(&vec_str(&[
            "sudo", "rm", "-rf", "/"
        ])));
        assert!(command_might_be_dangerous(&vec_str(&[
            "env", "FOO=bar", "rm", "-rf", "/"
        ])));
        assert!(command_might_be_dangerous(&vec_str(&[
            "env",
            "-u",
            "PATH",
            "dd",
            "of=/dev/sda"
        ])));
    }

    #[test]
    fn raw_disk_writers_are_dangerous() {
        assert!(command_might_be_dangerous(&vec_str(&[
            "dd",
            "if=/dev/zero",
            "of=/dev/sda"
        ])));
        assert!(command_might_be_dangerous(&vec_str(&[
            "mkfs.ext4",
            "/dev/sda1"
        ])));
        assert!(command_might_be_dangerous(&vec_str(&[
            "wipefs", "-a", "/dev/sda"
        ])));
        // dd that only reads is not flagged.
        assert!(!command_might_be_dangerous(&vec_str(&[
            "dd",
            "if=/dev/sda",
            "bs=512",
            "count=1"
        ])));
    }

    #[test]
    fn recursive_perm_changes_are_dangerous() {
        assert!(command_might_be_dangerous(&vec_str(&[
            "chmod", "-R", "000", "/"
        ])));
        assert!(command_might_be_dangerous(&vec_str(&[
            "chown",
            "--recursive",
            "root",
            "/etc"
        ])));
        // Non-recursive chmod is left to the normal flow.
        assert!(!command_might_be_dangerous(&vec_str(&[
            "chmod", "644", "file"
        ])));
    }

    #[test]
    fn forced_git_push_is_dangerous() {
        assert!(command_might_be_dangerous(&vec_str(&[
            "git", "push", "--force"
        ])));
        assert!(command_might_be_dangerous(&vec_str(&[
            "git", "push", "-f", "origin", "main"
        ])));
        assert!(command_might_be_dangerous(&vec_str(&[
            "git", "-C", "/repo", "push", "--delete", "origin", "branch"
        ])));
        // Ordinary push is not flagged by the backstop.
        assert!(!command_might_be_dangerous(&vec_str(&[
            "git", "push", "origin", "main"
        ])));
        // Read-only git is never flagged.
        assert!(!command_might_be_dangerous(&vec_str(&["git", "status"])));
    }

    #[test]
    fn sudo_options_are_skipped_before_rechecking() {
        // Options before the wrapped command must not hide it.
        assert!(command_might_be_dangerous(&vec_str(&[
            "sudo", "-E", "rm", "-rf", "/"
        ])));
        assert!(command_might_be_dangerous(&vec_str(&[
            "sudo", "--", "rm", "-rf", "/"
        ])));
        assert!(command_might_be_dangerous(&vec_str(&[
            "sudo", "-u", "root", "rm", "-rf", "/"
        ])));
        assert!(command_might_be_dangerous(&vec_str(&[
            "doas",
            "-u",
            "root",
            "dd",
            "of=/dev/sda"
        ])));
    }

    #[test]
    fn env_options_are_skipped_before_rechecking() {
        assert!(command_might_be_dangerous(&vec_str(&[
            "env",
            "--unset=PATH",
            "rm",
            "-rf",
            "/"
        ])));
        assert!(command_might_be_dangerous(&vec_str(&[
            "env", "-C", "/tmp", "rm", "-rf", "/"
        ])));
        assert!(command_might_be_dangerous(&vec_str(&[
            "env", "--", "rm", "-rf", "/"
        ])));
    }

    #[test]
    fn dangerous_push_refspecs_are_detected() {
        // Force update via leading `+`.
        assert!(command_might_be_dangerous(&vec_str(&[
            "git", "push", "origin", "+main"
        ])));
        // Delete via empty source (`:dst`).
        assert!(command_might_be_dangerous(&vec_str(&[
            "git",
            "push",
            "origin",
            ":old-branch"
        ])));
        // An ordinary `src:dst` refspec is not flagged.
        assert!(!command_might_be_dangerous(&vec_str(&[
            "git",
            "push",
            "origin",
            "main:main"
        ])));
    }

    #[test]
    fn bundled_recursive_perm_flags_are_dangerous() {
        assert!(command_might_be_dangerous(&vec_str(&[
            "chmod", "-Rf", "000", "/"
        ])));
        assert!(command_might_be_dangerous(&vec_str(&[
            "chown", "-hR", "root", "/u"
        ])));
        // A bundled group without `R` (e.g. `-f`) is not recursive.
        assert!(!command_might_be_dangerous(&vec_str(&[
            "chmod", "-f", "644", "file"
        ])));
    }

    #[test]
    fn dangerous_command_inside_bash_lc_script_is_detected() {
        assert!(command_might_be_dangerous(&vec_str(&[
            "bash",
            "-lc",
            "echo hi && rm -rf /tmp/x"
        ])));
    }

    #[test]
    fn direct_powershell_words_reuse_windows_dangerous_detection() {
        let command = vec_str(&["Remove-Item", "test", "-Force"]);

        if cfg!(windows) {
            assert!(is_dangerous_powershell_words(&command));
        } else {
            assert!(!is_dangerous_powershell_words(&command));
        }
    }
}
