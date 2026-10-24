use crate::Result;
use std::{
    fs::{self, File, Metadata, OpenOptions, Permissions},
    path::{Path, PathBuf},
};

pub fn reparse(info: &Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        info.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))]
    {
        info.file_type().is_symlink()
    }
}
pub fn directory(path: &Path) -> Result<()> {
    let info = fs::symlink_metadata(path).map_err(|_| "Directory unavailable")?;
    if !info.is_dir() || reparse(&info) {
        return Err("Unsafe directory");
    }
    Ok(())
}
pub fn same(a: &Metadata, b: &Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if a.dev() != b.dev() || a.ino() != b.ino() || a.nlink() != b.nlink() {
            return false;
        }
    }
    a.len() == b.len()
        && a.modified().ok() == b.modified().ok()
        && a.is_file() == b.is_file()
        && !reparse(b)
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Identity(u64, u64, u64);
fn identity(file: &File) -> Result<Identity> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let m = file.metadata().map_err(|_| "File identity unavailable")?;
        Ok(Identity(m.dev(), m.ino(), m.nlink()))
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
        };
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0
            || info.dwFileAttributes & 0x400 != 0
        {
            return Err("Unsafe Windows file handle");
        }
        Ok(Identity(
            u64::from(info.dwVolumeSerialNumber),
            (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
            u64::from(info.nNumberOfLinks),
        ))
    }
}
fn open(path: &Path, write_attributes: bool) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let _ = write_attributes;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
            FILE_WRITE_ATTRIBUTES,
        };
        options
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
            .share_mode(7)
            .access_mode(
                FILE_READ_ATTRIBUTES
                    | if write_attributes {
                        FILE_WRITE_ATTRIBUTES
                    } else {
                        0
                    }
                    | 0x80000000,
            );
    }
    options
        .open(path)
        .map_err(|_| "No-follow file handle unavailable")
}
pub fn open_regular(path: &Path, maximum: u64) -> Result<File> {
    open_regular_bounded(path, maximum, false)
}
pub fn open_regular_bounded(path: &Path, maximum: u64, allow_empty: bool) -> Result<File> {
    let before = fs::symlink_metadata(path).map_err(|_| "Regular file unavailable")?;
    if !before.is_file()
        || reparse(&before)
        || (!allow_empty && before.len() == 0)
        || before.len() > maximum
    {
        return Err("Expected bounded regular file");
    }
    let file = open(path, false)?;
    let actual = file.metadata().map_err(|_| "Regular file unavailable")?;
    if identity(&file)?.2 != 1 || !same(&before, &actual) {
        return Err("File replaced or hardlinked");
    }
    if identity(&file)? != identity(&open(path, false)?)? {
        return Err("File replaced during open");
    }
    Ok(file)
}
pub fn unchanged(file: &File, path: &Path) -> Result<()> {
    if identity(file)? != identity(&open(path, false)?)? {
        return Err("File identity changed");
    }
    Ok(())
}
pub fn single_link(file: &File) -> Result<()> {
    if identity(file)?.2 != 1 {
        return Err("Hardlinked workflow output");
    }
    Ok(())
}
pub fn safe_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 4096
        && path.split('/').count() <= 64
        && !path.starts_with('/')
        && !path.contains(['\\', ':', '\0'])
        && path.split('/').all(|p| {
            let stem = p.split('.').next().unwrap_or("").to_ascii_uppercase();
            !p.is_empty()
                && !matches!(p, "." | "..")
                && !p.eq_ignore_ascii_case(".git")
                && !p.ends_with(['.', ' '])
                && !p.chars().any(|c| c.is_control())
                && !matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
                && !(stem.len() == 4
                    && (stem.starts_with("COM") || stem.starts_with("LPT"))
                    && matches!(stem.as_bytes()[3], b'1'..=b'9'))
        })
}
struct FrozenEntry {
    path: PathBuf,
    id: Identity,
    permissions: Permissions,
}
pub struct Frozen {
    entries: Vec<FrozenEntry>,
}
fn permissions(file: &File, readonly: bool, original: &Permissions) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = if readonly {
            original.mode() & !0o222
        } else {
            original.mode()
        };
        file.set_permissions(Permissions::from_mode(mode))
            .map_err(|_| "Secure permissions unavailable")
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_BASIC_INFO, FileBasicInfo, GetFileInformationByHandleEx,
            SetFileInformationByHandle,
        };
        let mut info: FILE_BASIC_INFO = unsafe { std::mem::zeroed() };
        let handle = file.as_raw_handle();
        let size = std::mem::size_of::<FILE_BASIC_INFO>() as u32;
        if unsafe {
            GetFileInformationByHandleEx(
                handle,
                FileBasicInfo,
                (&mut info as *mut FILE_BASIC_INFO).cast(),
                size,
            )
        } == 0
        {
            return Err("Windows permissions unavailable");
        }
        if readonly || original.readonly() {
            info.FileAttributes |= 1;
        } else {
            info.FileAttributes &= !1;
        }
        if unsafe {
            SetFileInformationByHandle(
                handle,
                FileBasicInfo,
                (&info as *const FILE_BASIC_INFO).cast(),
                size,
            )
        } == 0
        {
            return Err("Windows permissions unavailable");
        }
        Ok(())
    }
}
impl Frozen {
    pub fn tree(root: &Path, parent: bool) -> Result<Self> {
        directory(root)?;
        let mut paths = Vec::new();
        let mut pending = vec![root.to_path_buf()];
        let mut dirs = 0;
        let mut files = 0;
        let mut total = 0;
        while let Some(dir) = pending.pop() {
            dirs += 1;
            if dirs > 2048 {
                return Err("Reviewed directory bound exceeded");
            }
            paths.push(dir.clone());
            for entry in fs::read_dir(&dir).map_err(|_| "Reviewed tree unavailable")? {
                let path = entry.map_err(|_| "Reviewed tree unavailable")?.path();
                let m = fs::symlink_metadata(&path).map_err(|_| "Reviewed entry unavailable")?;
                let relative = path
                    .strip_prefix(root)
                    .map_err(|_| "Reviewed path escapes root")?
                    .to_str()
                    .ok_or("Non-UTF8 reviewed path")?
                    .replace('\\', "/");
                if !safe_path(&relative) || reparse(&m) {
                    return Err("Unsafe reviewed path");
                }
                if m.is_dir() {
                    pending.push(path);
                } else if m.is_file() {
                    files += 1;
                    total += m.len();
                    if files > 1024 || m.len() > 4 * 1024 * 1024 || total > 16 * 1024 * 1024 {
                        return Err("Reviewed file bound exceeded");
                    }
                    paths.push(path);
                } else {
                    return Err("Unsafe reviewed file type");
                }
            }
        }
        if parent {
            let p = root.parent().ok_or("Reviewed parent missing")?;
            directory(p)?;
            paths.push(p.to_path_buf());
        }
        let mut guard = Self {
            entries: Vec::new(),
        };
        for path in paths {
            let file = open(&path, true)?;
            let m = file.metadata().map_err(|_| "Reviewed file unavailable")?;
            let id = identity(&file)?;
            if reparse(&m) || (!m.is_dir() && (!m.is_file() || id.2 != 1)) {
                return Err("Unsafe reviewed file identity");
            }
            let original = m.permissions();
            permissions(&file, true, &original)?;
            guard.entries.push(FrozenEntry {
                path,
                id,
                permissions: original,
            });
        }
        Ok(guard)
    }
    pub fn verify(&self) -> Result<()> {
        for entry in &self.entries {
            let file = open(&entry.path, false)?;
            if identity(&file)? != entry.id {
                return Err("Reviewed identity changed");
            }
            let permissions = file
                .metadata()
                .map_err(|_| "Reviewed file unavailable")?
                .permissions();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if permissions.mode() & 0o222 != 0 {
                    return Err("Reviewed source became writable");
                }
            }
            #[cfg(windows)]
            if !permissions.readonly() {
                return Err("Reviewed source became writable");
            }
        }
        Ok(())
    }
}
impl Drop for Frozen {
    fn drop(&mut self) {
        // Restore parents before children. Never follow a replacement during cleanup.
        self.entries.sort_by_key(|e| e.path.components().count());
        for entry in &self.entries {
            if let Ok(file) = open(&entry.path, true)
                && identity(&file).is_ok_and(|id| id == entry.id)
            {
                let _ = permissions(&file, false, &entry.permissions);
            }
        }
    }
}
