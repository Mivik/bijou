use std::{fmt, io};
use tracing::error;

macro_rules! anyhow {
    ($fmt:literal $($args:tt)*) => {
        $crate::anyhow!(@Unspecified $fmt $($args)*)
    };
    (@$kind:ident $fmt:literal $($args:tt)*) => {
        $crate::Error::new($crate::ErrorKind::$kind, Some(anyhow::anyhow!($fmt $($args)*)))
    };
    (@$kind:ident? $fmt:literal $($args:tt)*) => {
        $crate::Error::new($crate::ErrorKind::$kind, Some(anyhow::anyhow!($fmt $($args)*))).take_it_easy()
    };
    (@$kind:ident) => {
        $crate::Error::new($crate::ErrorKind::$kind, None)
    };
    (@$kind:ident?) => {
        $crate::Error::new($crate::ErrorKind::$kind, None).take_it_easy()
    };
}
pub(crate) use anyhow;

macro_rules! bail {
    ($($t:tt)*) => {
        return Err($crate::anyhow!($($t)*))
    };
}
pub(crate) use bail;

#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
    source: Option<anyhow::Error>,
    severe: bool,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.kind)?;
        if let Some(source) = &self.source {
            write!(f, ": {source}")?;
        }
        Ok(())
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_ref().map(|v| v.as_ref())
    }
}

impl Error {
    pub fn new(kind: ErrorKind, source: Option<anyhow::Error>) -> Self {
        Self {
            kind,
            source,
            severe: true,
        }
    }

    pub fn anyhow(source: anyhow::Error) -> Self {
        Self::new(ErrorKind::Unspecified, Some(source))
    }

    pub fn take_it_easy(mut self) -> Self {
        self.severe = false;
        self
    }

    pub fn msg<C>(msg: C) -> Self
    where
        C: fmt::Display + fmt::Debug + Send + Sync + 'static,
    {
        Self::anyhow(anyhow::Error::msg(msg))
    }

    pub fn context<C>(mut self, context: C) -> Self
    where
        C: fmt::Display + fmt::Debug + Send + Sync + 'static,
    {
        self.source = Some(match self.source {
            Some(err) => err.context(context),
            None => anyhow::Error::msg(context),
        });
        self
    }

    pub fn with_kind(mut self, kind: ErrorKind) -> Self {
        self.kind = kind;
        self
    }

    pub fn kind(&self) -> ErrorKind {
        self.kind
    }
}

pub trait ErrorExt {
    fn wrap(self) -> Error;
}
impl<E> ErrorExt for E
where
    E: std::error::Error + Send + Sync + 'static,
{
    fn wrap(self) -> Error {
        Error::anyhow(self.into())
    }
}
pub trait ResultExt<T> {
    fn wrap(self) -> Result<T>;
}
impl<T, E> ResultExt<T> for Result<T, E>
where
    E: std::error::Error + Send + Sync + 'static,
{
    fn wrap(self) -> Result<T> {
        self.map_err(|err| err.wrap())
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

pub trait Context<T> {
    fn kind(self, kind: ErrorKind) -> Result<T>;

    fn context<C>(self, context: C) -> Result<T>
    where
        C: fmt::Display + fmt::Debug + Send + Sync + 'static;

    fn with_context<C, F>(self, f: F) -> Result<T>
    where
        C: fmt::Display + fmt::Debug + Send + Sync + 'static,
        F: FnOnce() -> C;

    fn take_it_easy(self) -> Result<T>;
}

impl<T, E> Context<T> for Result<T, E>
where
    E: ErrorExt,
{
    fn kind(self, kind: ErrorKind) -> Result<T> {
        match self {
            Ok(ok) => Ok(ok),
            Err(error) => Err(error.wrap().with_kind(kind)),
        }
    }

    fn context<C>(self, context: C) -> Result<T>
    where
        C: fmt::Display + fmt::Debug + Send + Sync + 'static,
    {
        match self {
            Ok(ok) => Ok(ok),
            Err(error) => Err(error.wrap().context(context)),
        }
    }

    fn with_context<C, F>(self, context: F) -> Result<T, Error>
    where
        C: fmt::Display + fmt::Debug + Send + Sync + 'static,
        F: FnOnce() -> C,
    {
        match self {
            Ok(ok) => Ok(ok),
            Err(error) => Err(error.wrap().context(context())),
        }
    }

    fn take_it_easy(self) -> Result<T> {
        match self {
            Ok(ok) => Ok(ok),
            Err(error) => Err(error.wrap().take_it_easy()),
        }
    }
}

impl<T> Context<T> for Option<T> {
    fn kind(self, kind: ErrorKind) -> Result<T> {
        self.ok_or_else(|| Error::new(kind, None))
    }

    fn context<C>(self, context: C) -> Result<T>
    where
        C: fmt::Display + fmt::Debug + Send + Sync + 'static,
    {
        self.ok_or_else(|| Error::msg(context))
    }

    fn with_context<C, F>(self, context: F) -> Result<T, Error>
    where
        C: fmt::Display + fmt::Debug + Send + Sync + 'static,
        F: FnOnce() -> C,
    {
        self.ok_or_else(|| Error::msg(context()))
    }

    fn take_it_easy(self) -> Result<T> {
        self.ok_or_else(|| Error::new(ErrorKind::Unspecified, None).take_it_easy())
    }
}

impl Error {
    pub fn to_libc(&self) -> libc::c_int {
        if self.severe {
            error!("{self:?}");
        }
        if !matches!(self.kind, ErrorKind::Unspecified) {
            return self.kind.to_libc();
        }
        let Some(source) = self.source.as_ref() else {
            return libc::EIO;
        };

        if let Some(err) = source.downcast_ref::<rocksdb::Error>() {
            use rocksdb::ErrorKind::*;
            match err.kind() {
                NotFound => libc::ENOENT,
                NotSupported => libc::ENOTSUP,
                InvalidArgument => libc::EINVAL,
                IOError => libc::EIO,
                Busy => libc::EBUSY,
                TimedOut => libc::ETIMEDOUT,
                TryAgain => libc::EAGAIN,
                _ => libc::EIO,
            }
        } else if let Some(err) = source.downcast_ref::<std::io::Error>() {
            use std::io::ErrorKind::*;
            match err.kind() {
                NotFound => libc::ENOENT,
                AlreadyExists => libc::EEXIST,
                PermissionDenied => libc::EACCES,
                ConnectionRefused => libc::ECONNREFUSED,
                ConnectionReset => libc::ECONNRESET,
                ConnectionAborted => libc::ECONNABORTED,
                NotConnected => libc::ENOTCONN,
                AddrInUse => libc::EADDRINUSE,
                AddrNotAvailable => libc::EADDRNOTAVAIL,
                BrokenPipe => libc::EPIPE,
                WouldBlock => libc::EWOULDBLOCK,
                InvalidInput => libc::EINVAL,
                InvalidData => libc::EINVAL,
                TimedOut => libc::ETIMEDOUT,
                Interrupted => libc::EINTR,
                _ => libc::EIO,
            }
        } else {
            libc::EIO
        }
    }
}

#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
pub enum ErrorKind {
    #[default]
    Unspecified,

    DBError,
    CryptoError,
    IOError,

    IncompatibleVersion,

    AlreadyExists,
    BadFileDescriptor,
    InvalidInput,
    NotEmpty,
    NotFound,
    NotADirectory,
    FilesystemLoop,
}

impl ErrorKind {
    pub fn to_libc(&self) -> libc::c_int {
        use ErrorKind::*;
        match self {
            Unspecified => libc::EIO,

            DBError => libc::EIO,
            CryptoError => libc::EIO,
            IOError => libc::EIO,

            IncompatibleVersion => libc::EIO,

            AlreadyExists => libc::EEXIST,
            BadFileDescriptor => libc::EBADF,
            InvalidInput => libc::EINVAL,
            NotEmpty => libc::ENOTEMPTY,
            NotFound => libc::ENOENT,
            NotADirectory => libc::ENOTDIR,
            FilesystemLoop => libc::ELOOP,
        }
    }
}

impl From<ErrorKind> for io::ErrorKind {
    fn from(value: ErrorKind) -> Self {
        use io::ErrorKind as T;
        use ErrorKind as E;
        match value {
            E::IncompatibleVersion => T::Unsupported,

            E::AlreadyExists => T::AlreadyExists,
            E::InvalidInput => T::InvalidInput,
            E::NotFound => T::NotFound,

            _ => T::Other,
        }
    }
}

impl From<Error> for io::Error {
    fn from(value: Error) -> Self {
        io::Error::new(value.kind.into(), value)
    }
}
