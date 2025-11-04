use std::mem::MaybeUninit;
use std::sync::Mutex;

pub(super) type Buffer = Box<[MaybeUninit<u8>; 512]>;

pub(super) trait BufferExt {
    unsafe fn as_bytes(&self, len: usize) -> &[u8];
    fn as_bytes_mut(&mut self) -> &mut [u8];
}

impl BufferExt for Buffer {
    unsafe fn as_bytes(&self, len: usize) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.as_ptr() as *const u8, len) }
    }

    fn as_bytes_mut(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.as_ptr() as *mut u8, self.len()) }
    }
}

pub(crate) struct BufferPool {
    pool: Mutex<Vec<Buffer>>,
}

impl BufferPool {
    pub(super) fn new() -> Self {
        Self {
            pool: Mutex::new(Vec::new()),
        }
    }

    pub(super) fn get(&self) -> Buffer {
        self.pool
            .lock()
            .unwrap()
            .pop()
            .unwrap_or_else(|| Box::new(unsafe { MaybeUninit::uninit().assume_init() }) as Buffer)
    }

    pub(super) fn put(&self, buf: Buffer) {
        self.pool.lock().unwrap().push(buf);
    }
}
