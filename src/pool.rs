use crate::client::{AuthenticationError, Client, CommandError, ConnectError};
use deadpool::managed;
use thiserror::Error;

pub struct Manager {
    host: String,
    username: String,
    password: Option<String>,
}

impl Manager {
    /// Creates a new [`Manager`] that creates new NNTP clients on demand
    /// and authenticates them using the provided credentials.
    pub fn with_credentials(host: String, username: String, password: Option<String>) -> Self {
        Self {
            host,
            username,
            password,
        }
    }
}

#[derive(Error, Debug)]
pub enum PoolError {
    #[error("Connection failed: {0}")]
    Connection(ConnectError),
    #[error("Authentication failed: {0}")]
    Authentication(AuthenticationError),
    #[error("Connection recycling failed: {0}")]
    Recycling(CommandError),
}

impl managed::Manager for Manager {
    type Type = Client;
    type Error = PoolError;

    #[tracing::instrument(level = "trace", skip_all)]
    async fn create(&self) -> Result<Self::Type, Self::Error> {
        let mut client = Client::connect(&self.host)
            .await
            .map_err(PoolError::Connection)?;
        client
            .authenticate(&self.username, self.password.as_deref())
            .await
            .map_err(PoolError::Authentication)?;
        Ok(client)
    }

    /// Tries to recycle an NNTP client by sending a NOOP command.
    ///
    /// We assume that if the DATE command succeeds, the connection is still alive and can be reused.
    #[tracing::instrument(level = "trace", skip_all, fields(count = %metrics.recycle_count))]
    async fn recycle(
        &self,
        _client: &mut Self::Type,
        metrics: &managed::Metrics,
    ) -> managed::RecycleResult<Self::Error> {
        // NOTE: Explicitly checking that the connection is alive and accepts commands
        //       causes ~22ms delay per recycle, might not be worth it.
        // if let Err(err) = client.date().await {
        //     tracing::warn!("Recycling NNTP client failed: {}", err);
        //     return Err(managed::RecycleError::Backend(PoolError::RecyclingFailed(
        //         err,
        //     )));
        // }

        Ok(())
    }
}

pub type Pool = managed::Pool<Manager>;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires NNTP credentials"]
    async fn test_pool_creation() {
        crate::util::init_tracing();

        let host = std::env::var("NNTP_SERVER").unwrap();
        let username = std::env::var("NNTP_USERNAME").unwrap();
        let password = std::env::var("NNTP_PASSWORD").unwrap();

        let manager = Manager::with_credentials(host, username, Some(password));
        let pool = Pool::builder(manager).max_size(2).build().unwrap();

        let tasks = (0..4)
            .map(|i| {
                let pool = pool.clone();
                tokio::task::spawn(async move {
                    tracing::info!("Task {} is requesting a client from the pool", i);
                    let mut conn = pool.get().await.unwrap();
                    tracing::info!("Task {} acquired a client from the pool", i);

                    let date = conn.date().await.unwrap();
                    tracing::info!("Task {} got date: {}", i, date);
                })
            })
            .collect::<Vec<_>>();

        for task in tasks {
            task.await.unwrap();
        }
        tracing::info!("All tasks completed");
    }
}
