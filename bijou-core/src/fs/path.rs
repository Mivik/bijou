use std::{borrow::Borrow, fmt, ops, sync::Arc};

/// A single component of a [`Path`].
///
/// This corresponds to [`std::path::Component`].
#[derive(Debug, PartialEq, Eq, Hash)]
pub enum Component<'a> {
    RootDir,
    CurDir,
    ParentDir,
    Normal(&'a str),
}

impl<'a> Component<'a> {
    pub fn as_str(&self) -> &'a str {
        match self {
            Component::RootDir => "/",
            Component::CurDir => ".",
            Component::ParentDir => "..",
            Component::Normal(s) => s,
        }
    }
}

/// An iterator over the [`Component`]s of a [`Path`].
///
/// This corresponds to [`std::path::Components`].
pub struct Components<'a> {
    path: &'a str,
    at_start: bool,
}

impl<'a> Components<'a> {
    pub fn as_path(&self) -> &'a Path {
        Path::new(self.path)
    }

    fn parse_forward(&mut self, comp: &'a str) -> Option<Component<'a>> {
        let comp = match comp {
            "" => {
                if self.at_start {
                    Some(Component::RootDir)
                } else {
                    None
                }
            }
            "." => {
                if self.at_start {
                    Some(Component::CurDir)
                } else {
                    None
                }
            }
            ".." => Some(Component::ParentDir),
            _ => Some(Component::Normal(comp)),
        };
        self.at_start = false;
        comp
    }

    fn parse_backward(&mut self, comp: &'a str, no_rest: bool) -> Option<Component<'a>> {
        match comp {
            "" => {
                if self.at_start && no_rest {
                    Some(Component::RootDir)
                } else {
                    None
                }
            }
            "." => {
                if self.at_start && no_rest {
                    Some(Component::CurDir)
                } else {
                    None
                }
            }
            ".." => Some(Component::ParentDir),
            _ => Some(Component::Normal(comp)),
        }
    }
}

impl<'a> Iterator for Components<'a> {
    type Item = Component<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.path.is_empty() {
                return None;
            }
            let (comp, rest) = match self.path.find('/') {
                Some(index) => (&self.path[..index], &self.path[index + 1..]),
                None => (self.path, ""),
            };
            self.path = rest;
            if let Some(comp) = self.parse_forward(comp) {
                return Some(comp);
            }
        }
    }
}

impl<'a> DoubleEndedIterator for Components<'a> {
    fn next_back(&mut self) -> Option<Self::Item> {
        loop {
            if self.path.is_empty() {
                return None;
            }
            let (comp, rest) = match self.path.rfind('/') {
                Some(index) => (
                    &self.path[index + 1..],
                    &self.path[..(index + 1).min(self.path.len() - 1)],
                ),
                None => (self.path, ""),
            };
            self.path = rest;
            if let Some(comp) = self.parse_backward(comp, rest.is_empty()) {
                return Some(comp);
            }
        }
    }
}

/// A slice of path (akin to [`str`]).
///
/// Different from [`std::path::Path`], this type is always
/// UTF-8 encoded.
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct Path {
    inner: str,
}

impl Path {
    pub fn new<S: AsRef<str> + ?Sized>(s: &S) -> &Path {
        unsafe { &*(s.as_ref() as *const str as *const Path) }
    }

    pub fn as_str(&self) -> &str {
        &self.inner
    }

    pub fn components(&self) -> Components {
        Components {
            path: &self.inner,
            at_start: true,
        }
    }

    pub fn file_name(&self) -> Option<&str> {
        self.components().next_back().and_then(|p| match p {
            Component::Normal(p) => Some(p),
            _ => None,
        })
    }

    pub fn join(&self, other: impl AsRef<Path>) -> PathBuf {
        let other = other.as_ref();
        let mut buf = String::with_capacity(self.inner.len() + other.inner.len() + 1);
        buf.push_str(&self.inner);
        if !buf.ends_with('/') {
            buf.push('/');
        }
        buf.push_str(&other.inner);

        PathBuf { inner: buf }
    }

    pub fn parent(&self) -> Option<&Path> {
        let mut comps = self.components();
        let comp = comps.next_back();
        comp.and_then(move |p| match p {
            Component::Normal(_) | Component::CurDir | Component::ParentDir => {
                Some(comps.as_path())
            }
            _ => None,
        })
    }

    pub fn to_relative(&self) -> PathBuf {
        let mut comps = self.components();
        assert_eq!(Some(Component::RootDir), comps.next());
        let mut parts = Vec::new();
        for comp in comps {
            match comp {
                Component::Normal(p) => {
                    parts.push(p);
                }
                Component::ParentDir => {
                    parts.pop().unwrap();
                }
                _ => unreachable!(),
            }
        }
        if parts.is_empty() {
            return PathBuf::new(String::new());
        }

        let mut buf = String::with_capacity(parts.iter().map(|it| it.len() + 1).sum());
        for part in parts {
            buf.push_str(part);
            buf.push('/');
        }
        buf.pop();

        PathBuf { inner: buf }
    }
}

impl fmt::Display for Path {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner.fmt(f)
    }
}

impl<'a> From<&'a str> for &'a Path {
    fn from(value: &'a str) -> Self {
        Path::new(value)
    }
}

impl ToOwned for Path {
    type Owned = PathBuf;

    fn to_owned(&self) -> Self::Owned {
        PathBuf {
            inner: self.inner.to_owned(),
        }
    }
}

impl From<&Path> for Arc<Path> {
    #[inline]
    fn from(v: &Path) -> Arc<Path> {
        let arc = Arc::<str>::from(&v.inner);
        unsafe { Arc::from_raw(Arc::into_raw(arc) as *const Path) }
    }
}

impl AsRef<str> for Path {
    #[inline]
    fn as_ref(&self) -> &str {
        &self.inner[..]
    }
}

impl AsRef<Path> for Path {
    #[inline]
    fn as_ref(&self) -> &Path {
        self
    }
}

impl AsRef<std::path::Path> for Path {
    #[inline]
    fn as_ref(&self) -> &std::path::Path {
        std::path::Path::new(&self.inner)
    }
}

macro_rules! impl_as_ref {
    ($($t:ty),+) => {
        $(impl AsRef<Path> for $t {
            fn as_ref(&self) -> &Path {
                Path::new(self)
            }
        })+
    };
}
impl_as_ref!(str, String);

/// An owned, mutable [`Path`] (akin to [`String`]).
///
/// Different from [`std::path::PathBuf`], this type is always
/// UTF-8 encoded.
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct PathBuf {
    inner: String,
}

impl PathBuf {
    pub fn new(inner: String) -> Self {
        Self { inner }
    }

    pub fn pop(&mut self) -> bool {
        match self.parent().map(|p| p.as_str().len()) {
            Some(len) => {
                self.inner.truncate(len);
                true
            }
            None => false,
        }
    }
}

impl Borrow<Path> for PathBuf {
    fn borrow(&self) -> &Path {
        self
    }
}

impl ops::Deref for PathBuf {
    type Target = Path;
    #[inline]
    fn deref(&self) -> &Path {
        Path::new(&self.inner)
    }
}

impl AsRef<str> for PathBuf {
    #[inline]
    fn as_ref(&self) -> &str {
        &self.inner[..]
    }
}

impl AsRef<Path> for PathBuf {
    #[inline]
    fn as_ref(&self) -> &Path {
        self
    }
}

impl AsRef<std::path::Path> for PathBuf {
    #[inline]
    fn as_ref(&self) -> &std::path::Path {
        std::path::Path::new(&self.inner)
    }
}

impl From<String> for PathBuf {
    fn from(value: String) -> Self {
        Self { inner: value }
    }
}

impl From<&str> for PathBuf {
    fn from(value: &str) -> Self {
        Self {
            inner: value.to_owned(),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_back_components() {
        for path in ["../fds/", "./fs", "fs", "../", "..", ".", "./."] {
            let path = Path::new(path);
            let forward: Vec<_> = path.components().collect();
            let mut backward: Vec<_> = path.components().rev().collect();
            backward.reverse();
            assert_eq!(forward, backward);
        }
    }

    #[test]
    fn test_file_name() {
        assert_eq!(Some("c"), Path::new("../a/b/c").file_name());
        assert_eq!(Some("b"), Path::new("a/b/.").file_name());
        assert_eq!(None, Path::new("a/..").file_name());
    }
}
