use std::collections::HashMap;
use std::fs::{FileTimes, Permissions};
use std::io::{self, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH};

use russh_sftp::protocol::{
    Attrs, Data, File, FileAttributes, Handle, Name, OpenFlags, Status, StatusCode, Version,
};
use tokio::fs::{self, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

const MAX_READ: u32 = 256 * 1024;

enum Open {
    File(fs::File),
    Dir(Option<Vec<File>>),
}

pub struct Fs {
    root: PathBuf,
    handles: HashMap<String, Open>,
    next: u64,
}

impl Fs {
    pub fn new(root: PathBuf) -> Self {
        Fs {
            root,
            handles: HashMap::new(),
            next: 0,
        }
    }

    fn real(&self, path: &str) -> Result<PathBuf, StatusCode> {
        let virt = normalize(path)?;
        Ok(self.root.join(virt.trim_start_matches('/')))
    }

    fn insert(&mut self, open: Open) -> String {
        self.next += 1;
        let handle = self.next.to_string();
        self.handles.insert(handle.clone(), open);
        handle
    }

    fn file(&mut self, handle: &str) -> Result<&mut fs::File, StatusCode> {
        match self.handles.get_mut(handle) {
            Some(Open::File(file)) => Ok(file),
            _ => Err(StatusCode::Failure),
        }
    }
}

fn normalize(path: &str) -> Result<String, StatusCode> {
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            p if p.contains(':') || p.contains('\\') => return Err(StatusCode::PermissionDenied),
            p => parts.push(p),
        }
    }
    Ok(format!("/{}", parts.join("/")))
}

fn code(err: io::Error) -> StatusCode {
    match err.kind() {
        io::ErrorKind::NotFound => StatusCode::NoSuchFile,
        io::ErrorKind::PermissionDenied => StatusCode::PermissionDenied,
        _ => StatusCode::Failure,
    }
}

fn ok(id: u32) -> Status {
    Status {
        id,
        status_code: StatusCode::Ok,
        error_message: "Ok".into(),
        language_tag: "en-US".into(),
    }
}

async fn attrs(path: &Path) -> Result<FileAttributes, StatusCode> {
    let meta = fs::metadata(path).await.map_err(code)?;
    Ok(FileAttributes::from(&meta))
}

#[cfg(unix)]
fn permissions(_current: Permissions, mode: u32) -> Permissions {
    use std::os::unix::fs::PermissionsExt;
    Permissions::from_mode(mode & 0o7777)
}

#[cfg(not(unix))]
fn permissions(mut current: Permissions, mode: u32) -> Permissions {
    current.set_readonly(mode & 0o200 == 0);
    current
}

fn times(attrs: &FileAttributes) -> Option<FileTimes> {
    let at = |secs: u32| UNIX_EPOCH + Duration::from_secs(secs.into());
    Some(
        FileTimes::new()
            .set_accessed(at(attrs.atime?))
            .set_modified(at(attrs.mtime?)),
    )
}

async fn apply(file: &fs::File, attrs: &FileAttributes) -> io::Result<()> {
    if let Some(size) = attrs.size {
        file.set_len(size).await?;
    }
    if let Some(mode) = attrs.permissions {
        let current = file.metadata().await?.permissions();
        file.set_permissions(permissions(current, mode)).await?;
    }
    if let Some(times) = times(attrs) {
        let std_file = file.try_clone().await?.into_std().await;
        tokio::task::spawn_blocking(move || std_file.set_times(times))
            .await
            .map_err(io::Error::other)??;
    }
    Ok(())
}

impl russh_sftp::server::Handler for Fs {
    type Error = StatusCode;

    fn unimplemented(&self) -> Self::Error {
        StatusCode::OpUnsupported
    }

    async fn init(
        &mut self,
        _version: u32,
        _extensions: HashMap<String, String>,
    ) -> Result<Version, Self::Error> {
        Ok(Version::new())
    }

    async fn realpath(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        let files = vec![File::dummy(normalize(&path)?)];
        Ok(Name { id, files })
    }

    async fn stat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        let attrs = attrs(&self.real(&path)?).await?;
        Ok(Attrs { id, attrs })
    }

    async fn lstat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        self.stat(id, path).await
    }

    async fn fstat(&mut self, id: u32, handle: String) -> Result<Attrs, Self::Error> {
        let meta = self.file(&handle)?.metadata().await.map_err(code)?;
        let attrs = FileAttributes::from(&meta);
        Ok(Attrs { id, attrs })
    }

    async fn setstat(
        &mut self,
        id: u32,
        path: String,
        attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        let path = self.real(&path)?;
        if let Some(mode) = attrs.permissions {
            let current = fs::metadata(&path).await.map_err(code)?.permissions();
            fs::set_permissions(&path, permissions(current, mode))
                .await
                .map_err(code)?;
        }
        if attrs.size.is_some() || times(&attrs).is_some() {
            let file = OpenOptions::new()
                .write(true)
                .open(&path)
                .await
                .map_err(code)?;
            let rest = FileAttributes {
                permissions: None,
                ..attrs
            };
            apply(&file, &rest).await.map_err(code)?;
        }
        Ok(ok(id))
    }

    async fn fsetstat(
        &mut self,
        id: u32,
        handle: String,
        attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        let file = self.file(&handle)?;
        apply(file, &attrs).await.map_err(code)?;
        Ok(ok(id))
    }

    async fn opendir(&mut self, id: u32, path: String) -> Result<Handle, Self::Error> {
        let mut dir = fs::read_dir(self.real(&path)?).await.map_err(code)?;
        let mut files = Vec::new();
        while let Some(entry) = dir.next_entry().await.map_err(code)? {
            if let Ok(meta) = entry.metadata().await {
                let name = entry.file_name().to_string_lossy().into_owned();
                files.push(File::new(name, FileAttributes::from(&meta)));
            }
        }
        let handle = self.insert(Open::Dir(Some(files)));
        Ok(Handle { id, handle })
    }

    async fn readdir(&mut self, id: u32, handle: String) -> Result<Name, Self::Error> {
        match self.handles.get_mut(&handle) {
            Some(Open::Dir(files)) => match files.take() {
                Some(files) => Ok(Name { id, files }),
                None => Err(StatusCode::Eof),
            },
            _ => Err(StatusCode::Failure),
        }
    }

    async fn open(
        &mut self,
        id: u32,
        filename: String,
        pflags: OpenFlags,
        _attrs: FileAttributes,
    ) -> Result<Handle, Self::Error> {
        let path = self.real(&filename)?;
        let write = pflags.intersects(OpenFlags::WRITE | OpenFlags::APPEND);
        let create = pflags.contains(OpenFlags::CREATE);
        let file = OpenOptions::new()
            .read(pflags.contains(OpenFlags::READ) || !write)
            .write(write)
            .append(pflags.contains(OpenFlags::APPEND))
            .truncate(pflags.contains(OpenFlags::TRUNCATE))
            .create(create && !pflags.contains(OpenFlags::EXCLUDE))
            .create_new(create && pflags.contains(OpenFlags::EXCLUDE))
            .open(path)
            .await
            .map_err(code)?;
        let handle = self.insert(Open::File(file));
        Ok(Handle { id, handle })
    }

    async fn read(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        len: u32,
    ) -> Result<Data, Self::Error> {
        let file = self.file(&handle)?;
        file.seek(SeekFrom::Start(offset)).await.map_err(code)?;
        let mut data = vec![0; len.min(MAX_READ) as usize];
        let mut filled = 0;
        while filled < data.len() {
            let n = file.read(&mut data[filled..]).await.map_err(code)?;
            if n == 0 {
                break;
            }
            filled += n;
        }
        if filled == 0 {
            return Err(StatusCode::Eof);
        }
        data.truncate(filled);
        Ok(Data { id, data })
    }

    async fn write(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        data: Vec<u8>,
    ) -> Result<Status, Self::Error> {
        let file = self.file(&handle)?;
        file.seek(SeekFrom::Start(offset)).await.map_err(code)?;
        file.write_all(&data).await.map_err(code)?;
        Ok(ok(id))
    }

    async fn close(&mut self, id: u32, handle: String) -> Result<Status, Self::Error> {
        match self.handles.remove(&handle) {
            Some(Open::File(mut file)) => file.flush().await.map_err(code)?,
            Some(Open::Dir(_)) => {}
            None => return Err(StatusCode::Failure),
        }
        Ok(ok(id))
    }

    async fn remove(&mut self, id: u32, filename: String) -> Result<Status, Self::Error> {
        fs::remove_file(self.real(&filename)?).await.map_err(code)?;
        Ok(ok(id))
    }

    async fn mkdir(
        &mut self,
        id: u32,
        path: String,
        _attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        fs::create_dir(self.real(&path)?).await.map_err(code)?;
        Ok(ok(id))
    }

    async fn rmdir(&mut self, id: u32, path: String) -> Result<Status, Self::Error> {
        fs::remove_dir(self.real(&path)?).await.map_err(code)?;
        Ok(ok(id))
    }

    async fn rename(
        &mut self,
        id: u32,
        oldpath: String,
        newpath: String,
    ) -> Result<Status, Self::Error> {
        fs::rename(self.real(&oldpath)?, self.real(&newpath)?)
            .await
            .map_err(code)?;
        Ok(ok(id))
    }
}
