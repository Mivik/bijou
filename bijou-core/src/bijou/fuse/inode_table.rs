use super::{FileId, Inode};
use std::collections::{hash_map::Entry, HashMap, VecDeque};

#[derive(Debug)]
struct InodeItem {
    id: FileId,
    ref_count: u64,
    generation: u64,
}

/// A data structure maintaining a mapping between inodes and [`FileId`]s.
///
/// Inspired by <https://github.com/wfraser/fuse-mt/blob/master/src/inode_table.rs>.
// TODO optimize (lock-free concurrency)
pub struct InodeTable {
    items: Vec<InodeItem>,
    inode_table: HashMap<FileId, Inode>,

    bin: VecDeque<Inode>,
}

impl Default for InodeTable {
    fn default() -> Self {
        Self::new()
    }
}

impl InodeTable {
    pub fn new() -> Self {
        let mut items = Vec::new();
        let mut path_table = HashMap::new();

        let root_id = FileId::ROOT;
        items.push(InodeItem {
            id: root_id,
            ref_count: 1,
            generation: 0,
        });
        path_table.insert(root_id, Inode(1));

        Self {
            items,
            inode_table: path_table,

            bin: VecDeque::new(),
        }
    }

    fn allocate_inode(items: &mut Vec<InodeItem>, bin: &mut VecDeque<Inode>, id: FileId) -> Inode {
        match bin.pop_front() {
            Some(inode) => {
                let item = &mut items[inode.as_index()];
                item.id = id;
                item.generation += 1;
                inode
            }
            None => {
                items.push(InodeItem {
                    id,
                    ref_count: 0,
                    generation: 0,
                });
                Inode(items.len() as u64)
            }
        }
    }

    pub fn get_id(&self, inode: Inode) -> FileId {
        self.items[inode.as_index()].id
    }

    pub fn add(&mut self, id: FileId) -> (Inode, u64) {
        let (inode, generation) = {
            let inode = Self::allocate_inode(&mut self.items, &mut self.bin, id);
            let item = &mut self.items[inode.as_index()];
            item.ref_count = 1;
            (inode, item.generation)
        };

        if self.inode_table.insert(id, inode).is_some() {
            panic!("inserting duplicate ID into inode table: {id}")
        }

        (inode, generation)
    }

    pub fn get_or_insert(&mut self, id: FileId, lookup: bool) -> (Inode, u64) {
        let inode = match self.inode_table.entry(id) {
            Entry::Occupied(entry) => *entry.get(),
            Entry::Vacant(entry) => {
                let inode = Self::allocate_inode(&mut self.items, &mut self.bin, id);
                entry.insert(inode);
                inode
            }
        };

        let item = &mut self.items[inode.as_index()];
        if lookup && inode != Inode::ROOT {
            item.ref_count += 1;
        }
        (inode, item.generation)
    }

    pub fn forget(&mut self, inode: Inode, count: u64) {
        if inode == Inode::ROOT {
            return;
        }

        let item = &mut self.items[inode.as_index()];
        assert!(item.ref_count >= count);
        item.ref_count -= count;

        if item.ref_count == 0 {
            self.bin.push_back(inode);
            self.inode_table.remove(&item.id);
        }
    }

    pub fn unlink(&mut self, id: FileId) {
        self.inode_table.remove(&id);
    }
}
