use std::collections::HashMap;

use crate::ole2::stream_bytes::StreamChain;
use crate::ole2::walk::{FolderId, TOP_FOLDER};

const PROJECT_DIRECTORY_STREAM: &str = "dir";

#[derive(Debug, Clone)]
struct StoredStream {
    chain: StreamChain,
    name: Option<String>,
    ordinal: u32,
}

enum Item {
    Stream(StoredStream),
    Folder(FolderId),
}

pub struct Folders {
    items: Vec<Vec<Item>>,
    ordinals: HashMap<Option<String>, u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FolderOutput {
    Stream(StreamChain),
    ProjectText { dir: StreamChain, folder: FolderId },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FolderSteps {
    pub projects_are_read: bool,
    pub streams_are_scanned: bool,
}

impl Folders {
    pub fn new() -> Self {
        Self {
            items: vec![Vec::new()],
            ordinals: HashMap::new(),
        }
    }

    pub fn add_stream(&mut self, folder: FolderId, chain: StreamChain, name: Option<String>) {
        let ordinal = self.ordinals.entry(name.clone()).or_insert(0);
        *ordinal = ordinal.saturating_add(1);
        let stored = StoredStream {
            chain,
            name,
            ordinal: *ordinal,
        };
        if let Some(items) = self.items.get_mut(folder.0) {
            items.push(Item::Stream(stored));
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

    pub fn scan_order(self, steps: FolderSteps) -> FolderScan {
        FolderScan {
            folders: self,
            steps,
            tasks: vec![Task::Process(TOP_FOLDER)],
        }
    }

    fn items_of(&self, folder: FolderId) -> &[Item] {
        self.items.get(folder.0).map_or(&[], Vec::as_slice)
    }

    fn subfolders(&self, folder: FolderId) -> Vec<FolderId> {
        self.items_of(folder)
            .iter()
            .filter_map(|item| match item {
                Item::Folder(inner) => Some(*inner),
                Item::Stream(_) => None,
            })
            .collect()
    }

    fn project_directories_below(&self, folder: FolderId) -> Vec<(u32, StreamChain, FolderId)> {
        let mut found = Vec::new();
        let mut pending = vec![folder];
        while let Some(current) = pending.pop() {
            for item in self.items_of(current) {
                match item {
                    Item::Stream(stream)
                        if stream.name.as_deref() == Some(PROJECT_DIRECTORY_STREAM) =>
                    {
                        found.push((stream.ordinal, stream.chain, current));
                    }
                    Item::Stream(_) => {}
                    Item::Folder(inner) => pending.push(*inner),
                }
            }
        }
        found.sort_by_key(|(ordinal, _, _)| *ordinal);
        found
    }
}

enum Task {
    Process(FolderId),
    Projects(FolderId),
    Project { dir: StreamChain, folder: FolderId },
    Scan { folder: FolderId, item: usize },
}

pub struct FolderScan {
    folders: Folders,
    steps: FolderSteps,
    tasks: Vec<Task>,
}

impl FolderScan {
    pub fn streams_named(&self, folder: FolderId, name: &str) -> Vec<StreamChain> {
        self.folders
            .items_of(folder)
            .iter()
            .filter_map(|item| match item {
                Item::Stream(stream) if stream.name.as_deref() == Some(name) => Some(stream.chain),
                Item::Stream(_) | Item::Folder(_) => None,
            })
            .collect()
    }
}

impl Iterator for FolderScan {
    type Item = FolderOutput;

    fn next(&mut self) -> Option<FolderOutput> {
        while let Some(task) = self.tasks.pop() {
            match task {
                Task::Process(folder) => {
                    let subfolders = self.folders.subfolders(folder);
                    self.tasks
                        .extend(subfolders.into_iter().rev().map(Task::Process));
                    if self.steps.streams_are_scanned {
                        self.tasks.push(Task::Scan { folder, item: 0 });
                    }
                    if self.steps.projects_are_read {
                        self.tasks.push(Task::Projects(folder));
                    }
                }
                Task::Projects(folder) => {
                    let directories = self.folders.project_directories_below(folder);
                    self.tasks.extend(
                        directories
                            .into_iter()
                            .map(|(_, dir, folder)| Task::Project { dir, folder }),
                    );
                }
                Task::Project { dir, folder } => {
                    return Some(FolderOutput::ProjectText { dir, folder });
                }
                Task::Scan { folder, item } => {
                    let Some(found) = self.folders.items_of(folder).get(item) else {
                        continue;
                    };
                    self.tasks.push(Task::Scan {
                        folder,
                        item: item.saturating_add(1),
                    });
                    match found {
                        Item::Stream(stream) => return Some(FolderOutput::Stream(stream.chain)),
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
