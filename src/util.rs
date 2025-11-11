use tokio::io::AsyncBufReadExt;

use super::constants::{BLOCK_TERMINATOR, CRLF, MAX_INITIAL_LINE_LENGTH};

/// Reads a line from the reader into the buffer, expecting it to end with `CRLF`.
///
/// - The `CRLF` is removed from the buffer before returning.
/// - Returns the number of bytes read, excluding the `CRLF`.
pub async fn read_initial_line<R: AsyncBufReadExt + Unpin>(
    reader: &mut R,
    buffer: &mut Vec<u8>,
) -> Result<usize, std::io::Error> {
    let read = reader.read_until(b'\n', buffer).await?;

    if read == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "Unexpected end of stream while reading initial line",
        ));
    }

    if !buffer.ends_with(CRLF) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Initial line not terminated with CRLF",
        ));
    }

    buffer.truncate(buffer.len() - CRLF.len());
    Ok(read - CRLF.len())
}

#[cfg(test)]
pub fn init_tracing() {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;
    use tracing_subscriber::{EnvFilter, fmt};

    tracing_subscriber::registry()
        .with(fmt::layer().with_test_writer())
        .with(EnvFilter::from_default_env())
        .init();
}

/// Reads a dot-terminated data block from the reader into the buffer.
///
/// - Assumes that the initial line has already been read.
/// - Terminating `'.' + CRLF` is removed from the buffer.
/// - Dot-stuffing is undone (lines starting with `'.'` have the leading dot removed).
/// - Each line in the block ends with `CRLF`.
pub async fn read_multi_line_data_block<R: AsyncBufReadExt + Unpin>(
    reader: &mut R,
    buffer: &mut Vec<u8>,
) -> Result<usize, std::io::Error> {
    let mut line_buffer = Vec::with_capacity(MAX_INITIAL_LINE_LENGTH);
    let mut total_read = 0;

    loop {
        line_buffer.clear();
        let read = reader.read_until(b'\n', &mut line_buffer).await?;

        if read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "Unexpected end of stream while reading multi-line data block",
            ));
        }

        if !line_buffer.ends_with(CRLF) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Line in multi-line data block not terminated with CRLF",
            ));
        }

        // The lines of the block MUST be followed by a terminating line [...]
        if line_buffer == BLOCK_TERMINATOR {
            break;
        }

        // When a multi-line block is interpreted, the "dot-stuffing" MUST
        // be undone [...] that initial termination octet is disregarded.
        let data = if line_buffer.starts_with(b".") {
            &line_buffer[1..]
        } else {
            &line_buffer[..]
        };

        total_read += data.len();
        buffer.extend_from_slice(data);
    }

    Ok(total_read)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_read_initial_line() {
        let data = b"200 Service available\r\n";
        let mut buffer = Vec::new();

        let read = read_initial_line(&mut &data[..], &mut buffer)
            .await
            .unwrap();

        assert_eq!(buffer, b"200 Service available");
        assert_eq!(read, data.len() - CRLF.len());
    }

    #[tokio::test]
    async fn test_read_multi_line_data_block() {
        let data = b"Line 1\r\n.Line 2\r\nLine 3\r\n.\r\n";
        let mut buffer = Vec::new();

        let read = read_multi_line_data_block(&mut &data[..], &mut buffer)
            .await
            .unwrap();

        assert_eq!(buffer, b"Line 1\r\nLine 2\r\nLine 3\r\n");
        assert_eq!(read, data.len() - BLOCK_TERMINATOR.len() - 1);
    }

    #[tokio::test]
    async fn test_read_multi_line_data_block_empty() {
        let data = b".\r\n";
        let mut buffer = Vec::new();

        let read = read_multi_line_data_block(&mut &data[..], &mut buffer)
            .await
            .unwrap();

        assert_eq!(buffer, b"");
        assert_eq!(read, 0);
    }
}
