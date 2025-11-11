/// <https://datatracker.ietf.org/doc/html/rfc3977.html#section-3.1>
///
/// ```text
/// The initial line of the response MUST NOT exceed
/// 512 octets, which includes the response code and the terminating CRLF
/// pair; an extension MAY specify a greater maximum for commands that it
/// defines, but not for any other command.
/// ```
pub const MAX_INITIAL_LINE_LENGTH: usize = 512;

/// <https://datatracker.ietf.org/doc/html/rfc3977.html#section-3.1>
///
/// ```text
/// Each response MUST start with a three-digit response code that is
/// sufficient to distinguish all responses.
/// ```
pub const RESPONSE_CODE_LENGTH: usize = 3;

/// Carriage Return + Line Feed
pub const CRLF: &[u8] = b"\r\n";

/// <https://datatracker.ietf.org/doc/html/rfc3977.html#section-3.1.1>
///
/// ```text
/// 4.  The lines of the block MUST be followed by a terminating line
///     consisting of a single termination octet followed by a CRLF pair
///     in the normal way.  Thus, unless it is empty, a multi-line block
///     is always terminated with the five octets CRLF "." CRLF
///     (%x0D.0A.2E.0D.0A).
/// ```
pub const BLOCK_TERMINATOR: &[u8] = b".\r\n";

/// <https://datatracker.ietf.org/doc/html/rfc4642.html#section-1>
///
/// ```text
/// In some existing implementations, TCP port 563 has been dedicated to
/// NNTP over TLS.  These implementations begin the TLS negotiation
/// immediately upon connection and then continue with the initial steps
/// of an NNTP session.
/// ```
pub const NNTP_TLS_PORT: u16 = 563;
