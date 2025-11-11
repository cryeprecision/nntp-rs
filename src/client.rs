use std::sync::Arc;

use thiserror::Error;
use tokio::{io::AsyncWriteExt, net::TcpStream};
use tokio_rustls::{
    TlsConnector,
    client::TlsStream,
    rustls::{
        ClientConfig, RootCertStore,
        pki_types::{InvalidDnsNameError, ServerName},
    },
};

use crate::{
    article::ArticleHeaders,
    constants::{BLOCK_TERMINATOR, CRLF, MAX_INITIAL_LINE_LENGTH, NNTP_TLS_PORT},
    response::Response,
};

use super::command::Command;

pub struct Client {
    stream: TlsStream<TcpStream>,
}

#[derive(Error, Debug)]
pub enum ConnectError {
    #[error("TCP connection failed: {0}")]
    TcpConnectionFailed(std::io::Error),
    #[error("Invalid hostname: {0}")]
    InvalidHostname(InvalidDnsNameError),
    #[error("TLS handshake failed: {0}")]
    TlsHandshakeFailed(std::io::Error),
    #[error("IO error during connection: {0}")]
    IoError(std::io::Error),
    #[error("Service unavailable: {0:?}")]
    ServiceUnavailable(Response),
}

#[derive(Error, Debug)]
pub enum AuthenticationError {
    #[error("IO error during authentication: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Authentication failed: {0} ({1:?})")]
    AuthenticationFailed(&'static str, Response),
    #[error("Password required but not provided")]
    MissingPassword,
    #[error("Unexpected server response: {0:?}")]
    UnexpectedServerResponse(Response),
}

#[derive(Error, Debug)]
pub enum CommandError {
    #[error("IO error during command execution: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Unexpected server response: {0:?}")]
    UnexpectedServerResponse(Response),
}

#[derive(Error, Debug)]
pub enum PostError {
    #[error("IO error during posting: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Posting not permitted")]
    PostingNotPermitted,
    #[error("Posting failed")]
    PostingFailed,
    #[error("Unexpected server response: {0:?}")]
    UnexpectedServerResponse(Response),
}

impl Client {
    /// Connect to an NNTP server over TLS and wait for the server greeting.
    #[tracing::instrument(level = "debug")]
    pub async fn connect(host: &str) -> Result<Self, ConnectError> {
        let mut root_cert_store = RootCertStore::empty();
        root_cert_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let config = ClientConfig::builder()
            .with_root_certificates(root_cert_store)
            .with_no_client_auth();

        let connector = TlsConnector::from(Arc::new(config));
        let dns_name = ServerName::try_from(host).map_err(ConnectError::InvalidHostname)?;

        let host = format!("{host}:{port}", port = NNTP_TLS_PORT);

        tracing::trace!("Connecting to NNTP server at {host}");
        let stream = TcpStream::connect(host)
            .await
            .map_err(ConnectError::TcpConnectionFailed)?;

        tracing::trace!("TLS handshake with {dns_name:?}");
        let stream = connector
            .connect(dns_name.to_owned(), stream)
            .await
            .map_err(ConnectError::TlsHandshakeFailed)?;

        let mut client = Client { stream };

        tracing::trace!("Waiting for server greeting");
        let response = client
            .read_response()
            .await
            .map_err(ConnectError::IoError)?;
        match response {
            Response::ServiceAvailablePostingAllowed => {
                tracing::debug!("Server allows posting");
            }
            Response::ServiceAvailablePostingProhibited => {
                tracing::debug!("Server prohibits posting");
            }
            response => return Err(ConnectError::ServiceUnavailable(response)),
        };

        Ok(client)
    }

    /// Send an article (headers + body) to the server.
    ///
    /// - Appends a `CRLF` to the body if it does not already end with one
    /// - Does **not** send the initial POST command
    /// - Does **not** read the server response after sending the article
    #[tracing::instrument(level = "debug", skip_all, fields(message_id = %headers.message_id))]
    async fn send_article(
        &mut self,
        headers: &ArticleHeaders,
        body: &[u8],
    ) -> Result<(), std::io::Error> {
        // An article consists of two parts: the headers and the body.  They are
        // separated by a single empty line, or in other words by two
        // consecutive CRLF pairs (if there is more than one empty line, the
        // second and subsequent ones are part of the body).

        // Write the headers
        let mut buffer = Vec::with_capacity(MAX_INITIAL_LINE_LENGTH);
        headers.write(&mut buffer)?;

        // Write the empty line separating headers and body
        buffer.extend_from_slice(CRLF);

        // Write the body
        buffer.extend_from_slice(body);

        // Write an additional CRLF if the body does not end with one
        if !body.ends_with(CRLF) {
            buffer.extend_from_slice(CRLF);
        }

        // Terminate the article with the required dot-terminated line
        buffer.extend_from_slice(BLOCK_TERMINATOR);

        // Send the article to the server
        self.stream.write_all(&buffer).await?;
        self.stream.flush().await
    }

    /// Send a command to the server.
    pub async fn send_command(&mut self, command: Command<'_>) -> Result<(), std::io::Error> {
        command.write_command(&mut self.stream).await
    }

    /// Read a response from the server.
    pub async fn read_response(&mut self) -> Result<Response, std::io::Error> {
        Response::read_response(&mut self.stream).await
    }

    /// Authenticate with the server using the provided username and optional password.
    ///
    /// - If the server does not require a password, the `password` parameter can be `None`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub async fn authenticate(
        &mut self,
        username: &str,
        password: Option<&str>,
    ) -> Result<(), AuthenticationError> {
        // Send username and check if we need to send a password
        self.send_command(Command::AuthInfoUser(username)).await?;
        match self.read_response().await? {
            Response::PasswordRequired => (),
            Response::AuthenticationAccepted => {
                tracing::debug!("Authentication successful (no password required)");
                return Ok(());
            }
            Response::AuthenticationRejected => {
                return Err(AuthenticationError::AuthenticationFailed(
                    "Username rejected",
                    Response::AuthenticationRejected,
                ));
            }
            response => return Err(AuthenticationError::UnexpectedServerResponse(response)),
        }

        // Server requested a password, but none was provided
        let password = password.ok_or(AuthenticationError::MissingPassword)?;

        // Send password and check if authentication was successful
        self.send_command(Command::AuthInfoPass(password)).await?;
        match self.read_response().await? {
            Response::AuthenticationAccepted => (),
            Response::AuthenticationRejected => {
                return Err(AuthenticationError::AuthenticationFailed(
                    "Password rejected",
                    Response::AuthenticationRejected,
                ));
            }
            response => return Err(AuthenticationError::UnexpectedServerResponse(response)),
        }

        tracing::debug!("Authentication successful");
        Ok(())
    }

    /// Request help text from the server.
    #[tracing::instrument(level = "debug", skip_all)]
    pub async fn help(&mut self) -> Result<String, CommandError> {
        self.send_command(Command::Help).await?;
        match self.read_response().await? {
            Response::HelpText(help_text) => Ok(help_text),
            other => Err(CommandError::UnexpectedServerResponse(other)),
        }
    }

    /// Request server capabilities.
    #[tracing::instrument(level = "debug", skip_all)]
    pub async fn capabilities(&mut self) -> Result<Vec<String>, CommandError> {
        self.send_command(Command::Capabilities).await?;
        match self.read_response().await? {
            Response::Capabilities(capabilities) => Ok(capabilities),
            other => Err(CommandError::UnexpectedServerResponse(other)),
        }
    }

    /// Request the current server date and time.
    #[tracing::instrument(level = "debug", skip_all)]
    pub async fn date(&mut self) -> Result<chrono::NaiveDateTime, CommandError> {
        self.send_command(Command::Date).await?;
        match self.read_response().await? {
            Response::DateTime(datetime) => Ok(datetime),
            other => Err(CommandError::UnexpectedServerResponse(other)),
        }
    }

    /// Post an article (headers + body) to the server.
    #[tracing::instrument(level = "debug", skip_all)]
    pub async fn post(&mut self, headers: &ArticleHeaders, body: &[u8]) -> Result<(), PostError> {
        // Tell the server that we want to post an article
        self.send_command(Command::Post).await?;
        match self.read_response().await? {
            Response::SendArticleToBePosted => (),
            Response::PostingNotPermitted => return Err(PostError::PostingNotPermitted),
            Response::PostingFailed => return Err(PostError::PostingFailed),
            other => return Err(PostError::UnexpectedServerResponse(other)),
        }

        // Send the article (headers + body)
        self.send_article(headers, body).await?;

        // Check if the posting was successful
        match self.read_response().await? {
            Response::ArticleReceivedOk => (),
            Response::PostingFailed => return Err(PostError::PostingFailed),
            other => return Err(PostError::UnexpectedServerResponse(other)),
        }

        Ok(())
    }

    /// Fetch the body of an article by its message ID.
    ///
    /// - `message_id` must **not** include the angle brackets.
    #[tracing::instrument(level = "debug", skip_all)]
    pub async fn body(&mut self, message_id: &str) -> Result<Option<Vec<u8>>, CommandError> {
        self.send_command(Command::Body(message_id)).await?;
        match self.read_response().await? {
            Response::ArticleBody(body) => Ok(Some(body)),
            Response::MessageIdNotFound => Ok(None),
            other => Err(CommandError::UnexpectedServerResponse(other)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires NNTP credentials"]
    async fn test_connect() {
        crate::util::init_tracing();

        let host = std::env::var("NNTP_SERVER").unwrap();
        let username = std::env::var("NNTP_USERNAME").unwrap();
        let password = std::env::var("NNTP_PASSWORD").unwrap();

        let mut client = Client::connect(&host).await.unwrap();
        client
            .authenticate(&username, Some(&password))
            .await
            .unwrap();

        _ = client.date().await.unwrap();
    }
}
