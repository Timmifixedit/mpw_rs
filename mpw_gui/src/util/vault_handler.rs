use dashmap::DashMap;
use iced::Task;
use mpw_core::vault::Vault;
use std::sync::{Arc, Mutex, RwLock};

#[derive(Default)]
struct ResourceHandler {
    resources: DashMap<String, Arc<Mutex<()>>>,
}

impl ResourceHandler {
    pub fn get_mutex(&self, resource: Option<&str>) -> Option<Arc<Mutex<()>>> {
        let resource = resource?;
        self.resources
            .entry(resource.to_string())
            .or_insert_with(|| Arc::new(().into()))
            .value()
            .clone()
            .into()
    }
}

#[derive(Clone)]
pub struct VaultHandler {
    vault: Arc<RwLock<Vault>>,
    resource_handler: Arc<ResourceHandler>,
}

impl VaultHandler {
    pub fn new(vault: Vault) -> Self {
        Self {
            vault: Arc::new(vault.into()),
            resource_handler: ResourceHandler::default().into(),
        }
    }

    pub fn run_task<T: Send + 'static, M: Send + 'static>(
        &self,
        operation: impl FnOnce(&Vault) -> T + Send + 'static,
        resource: Option<&str>,
        message: impl FnOnce(T) -> M + Send + 'static,
    ) -> Task<M> {
        let vault = self.vault.clone();
        let mutex = self.resource_handler.get_mutex(resource);
        Task::perform(
            async move {
                let _guard = mutex
                    .as_ref()
                    .map(|mutex| Some(mutex.lock().expect("data mutex poisoned")));
                operation(&vault.read().expect("vault lock poisoned"))
            },
            message,
        )
    }

    pub fn run_task_mut<T: Send + 'static, M: Send + 'static>(
        &self,
        operation: impl FnOnce(&mut Vault) -> T + Send + 'static,
        resource: Option<&str>,
        message: impl FnOnce(T) -> M + Send + 'static,
    ) -> Task<M> {
        let vault = self.vault.clone();
        let mutex = self.resource_handler.get_mutex(resource);
        Task::perform(
            async move {
                let _guard = mutex
                    .as_ref()
                    .map(|mutex| Some(mutex.lock().expect("data mutex poisoned")));
                operation(&mut vault.write().expect("vault lock poisoned"))
            },
            message,
        )
    }

    pub async fn run_async<T: Send + 'static>(
        &self,
        operation: impl FnOnce(&Vault) -> T,
        resource: Option<&str>,
    ) -> T {
        let vault = self.vault.clone();
        let mutex = self.resource_handler.get_mutex(resource);
        async move {
            let _guard = mutex
                .as_ref()
                .map(|mutex| Some(mutex.lock().expect("data mutex poisoned")));
            operation(&vault.read().expect("vault lock poisoned"))
        }
        .await
    }

    pub async fn run_async_mut<T>(
        &self,
        operation: impl FnOnce(&mut Vault) -> T,
        resource: Option<&str>,
    ) -> T {
        let vault = self.vault.clone();
        let mutex = self.resource_handler.get_mutex(resource);
        async move {
            let _guard = mutex
                .as_ref()
                .map(|mutex| Some(mutex.lock().expect("data mutex poisoned")));
            operation(&mut vault.write().expect("vault lock poisoned"))
        }
        .await
    }

    pub fn blocking_operation<T>(&self, operation: impl FnOnce(&Vault) -> T) -> T {
        operation(&self.vault.read().expect("vault lock poisoned"))
    }

    pub fn blocking_operation_mut<T>(&mut self, operation: impl FnOnce(&mut Vault) -> T) -> T {
        operation(&mut self.vault.write().expect("vault lock poisoned"))
    }
}
