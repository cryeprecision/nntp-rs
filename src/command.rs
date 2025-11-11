use tokio::io::AsyncWriteExt;

use crate::constants::{CRLF, MAX_INITIAL_LINE_LENGTH};

pub enum Command<'a> {
    /// <https://datatracker.ietf.org/doc/html/rfc4643.html#section-2.3.1>
    ///
    /// Sends the username for authentication.
    AuthInfoUser(&'a str),
    /// <https://datatracker.ietf.org/doc/html/rfc4643.html#section-2.3.1>
    ///
    /// Sends the password for authentication.
    AuthInfoPass(&'a str),
    /// <https://datatracker.ietf.org/doc/html/rfc3977.html#section-5.2>
    Capabilities,
    /// <https://datatracker.ietf.org/doc/html/rfc3977.html#section-7.2>
    Help,
    /// <https://datatracker.ietf.org/doc/html/rfc3977.html#section-7.1>
    Date,
    /// <https://datatracker.ietf.org/doc/html/rfc3977.html#section-6.3.1>
    Post,
    /// <https://datatracker.ietf.org/doc/html/rfc3977.html#section-6.2.3>
    ///
    /// Fetches the body for the specified message-id.
    Body(&'a str),
}

// Hide sensitive information in debug output
impl std::fmt::Debug for Command<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Command::AuthInfoUser(_) => f.debug_tuple("AuthInfoUser").field(&"*******").finish(),
            Command::AuthInfoPass(_) => f.debug_tuple("AuthInfoPass").field(&"*******").finish(),
            Command::Capabilities => f.debug_tuple("Capabilities").finish(),
            Command::Help => f.debug_tuple("Help").finish(),
            Command::Date => f.debug_tuple("Date").finish(),
            Command::Post => f.debug_tuple("Post").finish(),
            Command::Body(id) => f.debug_tuple("Body").field(id).finish(),
        }
    }
}

impl Command<'_> {
    #[tracing::instrument(level = "debug", skip(writer))]
    pub async fn write_command<W: AsyncWriteExt + Unpin>(
        &self,
        writer: &mut W,
    ) -> Result<(), std::io::Error> {
        tracing::trace!("Sending NNTP command: {:?}", self);

        let mut buffer = Vec::with_capacity(MAX_INITIAL_LINE_LENGTH);
        match self {
            Command::AuthInfoUser(username) => {
                buffer.extend_from_slice(b"AUTHINFO USER ");
                buffer.extend_from_slice(username.as_bytes());
            }
            Command::AuthInfoPass(password) => {
                buffer.extend_from_slice(b"AUTHINFO PASS ");
                buffer.extend_from_slice(password.as_bytes());
            }
            Command::Capabilities => buffer.extend_from_slice(b"CAPABILITIES"),
            Command::Help => buffer.extend_from_slice(b"HELP"),
            Command::Date => buffer.extend_from_slice(b"DATE"),
            Command::Post => buffer.extend_from_slice(b"POST"),
            Command::Body(message_id) => {
                buffer.extend_from_slice(b"BODY ");
                buffer.extend_from_slice(b"<");
                buffer.extend_from_slice(message_id.as_bytes());
                buffer.extend_from_slice(b">");
            }
        };
        buffer.extend_from_slice(CRLF);

        writer.write_all(&buffer).await?;
        writer.flush().await
    }
}
