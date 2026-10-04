use crate::session::default_exclusions;
use crate::sha256_hex;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkspaceFile {
    pub relative_path: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkspaceManifest {
    pub source_root: PathBuf,
    pub snapshot_root: PathBuf,
    pub files: Vec<WorkspaceFile>,
    pub excluded_paths: Vec<String>,
    pub snapshot_hash: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum DiffKind {
    Added,
    Modified,
    Deleted,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiffEntry {
    pub relative_path: String,
    pub kind: DiffKind,
    pub before_sha256: Option<String>,
    pub after_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkspaceDiff {
    pub source_root: PathBuf,
    pub snapshot_root: PathBuf,
    pub entries: Vec<DiffEntry>,
    pub diff_hash: String,
}

pub fn snapshot_workspace(
    source: &Path,
    snapshot: &Path,
    exclusions: &[String],
) -> Result<WorkspaceManifest, String> {
    if !source.is_dir() {
        return Err(format!(
            "workspace is not a directory: {}",
            source.display()
        ));
    }
    if snapshot.exists() {
        fs::remove_dir_all(snapshot).map_err(|error| error.to_string())?;
    }
    fs::create_dir_all(snapshot).map_err(|error| error.to_string())?;
    let files = copy_tree(source, snapshot, source, exclusions)?;
    let snapshot_hash = hash_files(&files);
    Ok(WorkspaceManifest {
        source_root: source.to_path_buf(),
        snapshot_root: snapshot.to_path_buf(),
        files,
        excluded_paths: exclusions.to_vec(),
        snapshot_hash,
    })
}

pub fn collect_diff(
    source: &Path,
    snapshot: &Path,
    exclusions: &[String],
) -> Result<WorkspaceDiff, String> {
    let source_files = collect_files(source, source, exclusions)?;
    let snapshot_files = collect_files(snapshot, snapshot, exclusions)?;
    let before = source_files
        .into_iter()
        .map(|file| (file.relative_path.clone(), file))
        .collect::<BTreeMap<_, _>>();
    let after = snapshot_files
        .into_iter()
        .map(|file| (file.relative_path.clone(), file))
        .collect::<BTreeMap<_, _>>();
    let mut entries = Vec::new();

    for (path, before_file) in &before {
        match after.get(path) {
            None => entries.push(DiffEntry {
                relative_path: path.clone(),
                kind: DiffKind::Deleted,
                before_sha256: Some(before_file.sha256.clone()),
                after_sha256: None,
            }),
            Some(after_file) if before_file.sha256 != after_file.sha256 => {
                entries.push(DiffEntry {
                    relative_path: path.clone(),
                    kind: DiffKind::Modified,
                    before_sha256: Some(before_file.sha256.clone()),
                    after_sha256: Some(after_file.sha256.clone()),
                })
            }
            Some(_) => {}
        }
    }
    for (path, after_file) in &after {
        if !before.contains_key(path) {
            entries.push(DiffEntry {
                relative_path: path.clone(),
                kind: DiffKind::Added,
                before_sha256: None,
                after_sha256: Some(after_file.sha256.clone()),
            });
        }
    }
    entries.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    let diff_hash = sha256_hex(&serde_json::to_vec(&entries).map_err(|error| error.to_string())?);
    Ok(WorkspaceDiff {
        source_root: source.to_path_buf(),
        snapshot_root: snapshot.to_path_buf(),
        entries,
        diff_hash,
    })
}

pub fn apply_diff(
    source: &Path,
    snapshot: &Path,
    diff: &WorkspaceDiff,
    selected_paths: &[String],
) -> Result<(), String> {
    let selected = diff
        .entries
        .iter()
        .filter(|entry| is_selected(&entry.relative_path, selected_paths))
        .collect::<Vec<_>>();

    // Pre-flight every selected entry before touching the host. A conflict or
    // an unsafe path must abort the whole writeback; a partially applied diff
    // would leave the workspace in a state the audit record does not describe.
    let mut planned = Vec::with_capacity(selected.len());
    for entry in selected {
        let relative = safe_relative_path(&entry.relative_path)?;
        ensure_no_symlink_components(source, &relative)?;
        verify_host_unchanged(source, &relative, entry)?;
        planned.push((entry, relative));
    }

    for (entry, relative) in planned {
        let source_path = source.join(&relative);
        let snapshot_path = snapshot.join(&relative);
        match entry.kind {
            DiffKind::Added | DiffKind::Modified => {
                let parent = source_path
                    .parent()
                    .ok_or_else(|| format!("invalid destination: {}", source_path.display()))?;
                fs::create_dir_all(parent).map_err(|error| error.to_string())?;
                fs::copy(&snapshot_path, &source_path).map_err(|error| error.to_string())?;
            }
            DiffKind::Deleted => {
                if source_path.exists() {
                    fs::remove_file(&source_path).map_err(|error| error.to_string())?;
                }
            }
        }
    }
    Ok(())
}

pub fn is_excluded_path(relative: &Path, exclusions: &[String]) -> bool {
    let components = relative
        .components()
        .filter_map(|component| match component {
            Component::Normal(value) => value.to_str(),
            _ => None,
        })
        .collect::<Vec<_>>();
    components.iter().any(|component| {
        exclusions.iter().any(|excluded| {
            excluded == component
                || (excluded == ".env.*" && component.starts_with(".env."))
                || (excluded.contains('/') && relative.to_string_lossy().starts_with(excluded))
        })
    })
}

fn copy_tree(
    root: &Path,
    target: &Path,
    current: &Path,
    exclusions: &[String],
) -> Result<Vec<WorkspaceFile>, String> {
    let mut files = Vec::new();
    for entry in fs::read_dir(current).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        let path = entry.path();
        let relative = path.strip_prefix(root).map_err(|error| error.to_string())?;
        if is_excluded_path(relative, exclusions) {
            continue;
        }
        let metadata = fs::symlink_metadata(&path).map_err(|error| error.to_string())?;
        if metadata.file_type().is_symlink() {
            continue;
        }
        let destination = target.join(relative);
        if metadata.is_dir() {
            fs::create_dir_all(&destination).map_err(|error| error.to_string())?;
            files.extend(copy_tree(root, target, &path, exclusions)?);
        } else if metadata.is_file() {
            if let Some(parent) = destination.parent() {
                fs::create_dir_all(parent).map_err(|error| error.to_string())?;
            }
            fs::copy(&path, &destination).map_err(|error| error.to_string())?;
            files.push(file_metadata(root, &path)?);
        }
    }
    Ok(files)
}

fn collect_files(
    root: &Path,
    current: &Path,
    exclusions: &[String],
) -> Result<Vec<WorkspaceFile>, String> {
    let mut files = Vec::new();
    for entry in fs::read_dir(current).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        let path = entry.path();
        let relative = path.strip_prefix(root).map_err(|error| error.to_string())?;
        if is_excluded_path(relative, exclusions) {
            continue;
        }
        let metadata = fs::symlink_metadata(&path).map_err(|error| error.to_string())?;
        if metadata.file_type().is_symlink() {
            continue;
        }
        if metadata.is_dir() {
            files.extend(collect_files(root, &path, exclusions)?);
        } else if metadata.is_file() {
            files.push(file_metadata(root, &path)?);
        }
    }
    Ok(files)
}

fn file_metadata(root: &Path, path: &Path) -> Result<WorkspaceFile, String> {
    let content = fs::read(path).map_err(|error| error.to_string())?;
    let metadata = fs::metadata(path).map_err(|error| error.to_string())?;
    Ok(WorkspaceFile {
        relative_path: path
            .strip_prefix(root)
            .map_err(|error| error.to_string())?
            .to_string_lossy()
            .replace('\\', "/"),
        size: metadata.len(),
        sha256: sha256_hex(&content),
    })
}

fn hash_files(files: &[WorkspaceFile]) -> String {
    sha256_hex(&serde_json::to_vec(files).unwrap_or_default())
}

fn is_selected(relative_path: &str, selected_paths: &[String]) -> bool {
    selected_paths.iter().any(|selected| {
        selected == relative_path || relative_path.starts_with(&format!("{selected}/"))
    })
}

/// Rejects any selected path whose parent chain escapes the workspace through a
/// symlink. `safe_relative_path` only checks how the path is spelled, so a link
/// created inside the workspace while a session runs could otherwise redirect
/// the writeback outside it.
fn ensure_no_symlink_components(root: &Path, relative: &Path) -> Result<(), String> {
    let mut current = root.to_path_buf();
    for component in relative.components() {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(format!(
                    "拒绝写回：{} 是符号链接，写回可能落到工作区之外。请先移除该链接或改选其它路径。",
                    current.display()
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!("无法检查路径 {}: {error}", current.display()));
            }
        }
    }
    Ok(())
}

/// Confirms the host file still matches the state recorded in the diff. The
/// diff is computed from the snapshot, so a host file edited after the diff was
/// taken would otherwise be silently overwritten by `apply`.
fn verify_host_unchanged(source: &Path, relative: &Path, entry: &DiffEntry) -> Result<(), String> {
    let target = source.join(relative);
    let current = match fs::read(&target) {
        Ok(bytes) => Some(sha256_hex(&bytes)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(format!("无法读取宿主文件 {}: {error}", target.display())),
    };
    match (&entry.before_sha256, current) {
        (None, None) => Ok(()),
        (Some(expected), Some(actual)) if expected == &actual => Ok(()),
        (None, Some(_)) => Err(format!(
            "宿主文件已变更，拒绝写回 {}：diff 记录该路径为新增，但宿主已存在同名文件。请重新运行 session diff 并确认后再 apply。",
            target.display()
        )),
        (Some(_), None) => Err(format!(
            "宿主文件已变更，拒绝写回 {}：diff 记录的宿主文件已不存在。请重新运行 session diff 并确认后再 apply。",
            target.display()
        )),
        (Some(expected), Some(actual)) => Err(format!(
            "宿主文件已被修改，拒绝写回 {}：diff 期望 before={expected}，当前={actual}。请重新运行 session diff 并确认后再 apply。",
            target.display()
        )),
    }
}

fn safe_relative_path(path: &str) -> Result<PathBuf, String> {
    let path = Path::new(path);
    if path.as_os_str().is_empty() {
        return Err("unsafe relative path: empty".into());
    }
    if path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(format!("unsafe relative path: {}", path.display()));
    }
    Ok(path.to_path_buf())
}

#[allow(dead_code)]
fn _default_exclusions_are_available() -> Vec<String> {
    default_exclusions()
}
