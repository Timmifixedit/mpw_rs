use iced::Task;
use mpw_core::vault::Vault;
use std::sync::{Arc, Mutex, RwLock};

#[derive(Clone)]
pub struct VaultHandler {
    vault: Arc<RwLock<Vault>>,
    data_mutex: Arc<Mutex<()>>,
}

impl VaultHandler {
    pub fn new(vault: Vault) -> Self {
        Self {
            vault: Arc::new(vault.into()),
            data_mutex: Mutex::new(()).into(),
        }
    }

    pub fn run_task<T: Send + 'static, M: Send + 'static>(
        &self,
        operation: impl FnOnce(&Vault) -> T + Send + 'static,
        message: impl FnOnce(T) -> M + Send + 'static,
    ) -> Task<M> {
        let vault = self.vault.clone();
        Task::perform(
            async move { operation(&vault.read().expect("vault lock poisoned")) },
            message,
        )
    }

    pub fn run_exclusive_task<T: Send + 'static, M: Send + 'static>(
        &self,
        operation: impl FnOnce(&Vault) -> T + Send + 'static,
        message: impl FnOnce(T) -> M + Send + 'static,
    ) -> Task<M> {
        let mutex = self.data_mutex.clone();
        let vault = self.vault.clone();
        Task::perform(
            async move {
                let _guard = mutex.lock().expect("data mutex poisoned");
                operation(&vault.read().expect("vault lock poisoned"))
            },
            message,
        )
    }

    pub fn run_task_mut<T: Send + 'static, M: Send + 'static>(
        &mut self,
        operation: impl FnOnce(&mut Vault) -> T + Send + 'static,
        message: impl FnOnce(T) -> M + Send + 'static,
    ) -> Task<M> {
        let vault = self.vault.clone();
        Task::perform(
            async move { operation(&mut vault.write().expect("vault lock poisoned")) },
            message,
        )
    }

    pub fn blocking_operation<T>(&self, operation: impl FnOnce(&Vault) -> T) -> T {
        operation(&self.vault.read().expect("vault lock poisoned"))
    }

    pub fn blocking_operation_mut<T>(&mut self, operation: impl FnOnce(&mut Vault) -> T) -> T {
        operation(&mut self.vault.write().expect("vault lock poisoned"))
    }
}
