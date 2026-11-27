use crate::ole2::stream_bytes::StreamChain;
use crate::ole2::walk::{FolderId, TOP_FOLDER};

enum Item {
    Stream(StreamChain),
    Folder(FolderId),
}

pub struct Folders {
    items: Vec<Vec<Item>>,
}

impl Folders {
    pub fn new() -> Self {
        Self {
            items: vec![Vec::new()],
        }
    }

    pub fn add_stream(&mut self, folder: FolderId, chain: StreamChain) {
        if let Some(items) = self.items.get_mut(folder.0) {
            items.push(Item::Stream(chain));
        }
    }

    pub fn add_folder(&mut self, folder: FolderId, inner: FolderId) {
        while self.items.len() <= inner.0 {
            self.items.push(Vec::new());
        }
        if let Some(items) = self.items.get_mut(folder.0) {
            items.push(Item::Folder(inner));
        }
    }

    pub fn scan_order(self, each_folder_scanned: bool) -> FolderScan {
        FolderScan {
            folders: self,
            each_folder_scanned,
            tasks: vec![Task::Process(TOP_FOLDER)],
        }
    }

    fn subfolders(&self, folder: FolderId) -> impl DoubleEndedIterator<Item = FolderId> + '_ {
        self.items
            .get(folder.0)
            .into_iter()
            .flatten()
            .filter_map(|item| match item {
                Item::Folder(inner) => Some(*inner),
                Item::Stream(_) => None,
            })
    }
}

enum Task {
    Process(FolderId),
    Scan { folder: FolderId, item: usize },
}

pub struct FolderScan {
    folders: Folders,
    each_folder_scanned: bool,
    tasks: Vec<Task>,
}

impl Iterator for FolderScan {
    type Item = StreamChain;

    fn next(&mut self) -> Option<StreamChain> {
        while let Some(task) = self.tasks.pop() {
            match task {
                Task::Process(folder) => {
                    let subfolders: Vec<FolderId> = self.folders.subfolders(folder).rev().collect();
                    self.tasks.extend(subfolders.into_iter().map(Task::Process));
                    if self.each_folder_scanned {
                        self.tasks.push(Task::Scan { folder, item: 0 });
                    }
                }
                Task::Scan { folder, item } => {
                    let Some(found) = self
                        .folders
                        .items
                        .get(folder.0)
                        .and_then(|items| items.get(item))
                    else {
                        continue;
                    };
                    self.tasks.push(Task::Scan {
                        folder,
                        item: item.saturating_add(1),
                    });
                    match found {
                        Item::Stream(chain) => return Some(*chain),
                        Item::Folder(inner) => self.tasks.push(Task::Scan {
                            folder: *inner,
                            item: 0,
                        }),
                    }
                }
            }
        }
        None
    }
}
