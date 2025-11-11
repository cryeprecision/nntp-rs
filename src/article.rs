use crate::constants::CRLF;

/// - Does not include the [Path header](https://datatracker.ietf.org/doc/html/rfc5536#section-3.1.5)
pub struct ArticleHeaders {
    /// <https://datatracker.ietf.org/doc/html/rfc5536#section-3.1.1>
    pub datetime: chrono::DateTime<chrono::Utc>,
    /// <https://datatracker.ietf.org/doc/html/rfc5536#section-3.1.2>
    pub from: String,
    /// <https://datatracker.ietf.org/doc/html/rfc5536#section-3.1.3>
    pub message_id: String,
    /// <https://datatracker.ietf.org/doc/html/rfc5536#section-3.1.4>
    pub newsgroups: Vec<String>,
    /// <https://datatracker.ietf.org/doc/html/rfc5536#section-3.1.6>
    pub subject: String,
}

impl ArticleHeaders {
    /// ```text
    /// The headers of an article consist of one or more header lines.  Each
    /// header line consists of a header name, a colon, a space, the header
    /// content, and a CRLF, in that order.
    /// ```
    fn write_header<F>(
        buffer: &mut Vec<u8>,
        name: &'static str,
        value_writer: F,
    ) -> Result<(), std::io::Error>
    where
        F: FnOnce(&mut Vec<u8>) -> Result<(), std::io::Error>,
    {
        buffer.extend_from_slice(name.as_bytes());
        buffer.extend_from_slice(b": ");
        value_writer(buffer)?;
        buffer.extend_from_slice(CRLF);
        Ok(())
    }

    /// Write the article headers into the provided buffer.
    ///
    /// - Includes a `CRLF` at the end of every header line (including the last one).
    ///
    /// # Example
    ///
    /// ```text
    /// Date: Wed, 15 Mar 2023 12:00:42 +0000\r\n
    /// From: userabc@def.ghi\r\n
    /// Message-ID: <randomid@jkl.mno>\r\n
    /// Newsgroups: test.group1,test.group2\r\n
    /// Path: \r\n
    /// Subject: randomsubject@pqr.stu\r\n
    /// ```
    pub fn write(&self, buffer: &mut Vec<u8>) -> Result<(), std::io::Error> {
        // A message-id MUST begin with "<", end with ">", and MUST NOT
        // contain the latter except at the end.
        if self.message_id.contains('>') {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Message-ID contains invalid character '>'",
            ));
        }

        // A message-id MUST be between 3 and 250 octets in length.
        if self.message_id.len() < 3 || self.message_id.len() > 250 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Message-ID length is out of bounds (3-250 octets)",
            ));
        }

        // A message-id MUST NOT contain octets other than printable US-ASCII
        // characters.
        if !self.message_id.is_ascii() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Message-ID contains non-ASCII characters",
            ));
        }

        // https://datatracker.ietf.org/doc/html/rfc5536#section-3.1.1
        Self::write_header(buffer, "Date", |buf| {
            let datetime_str = self.datetime.to_rfc2822();
            buf.extend_from_slice(datetime_str.as_bytes());
            Ok(())
        })?;

        // https://datatracker.ietf.org/doc/html/rfc5536#section-3.1.2
        Self::write_header(buffer, "From", |buf| {
            buf.extend_from_slice(self.from.as_bytes());
            Ok(())
        })?;

        // https://datatracker.ietf.org/doc/html/rfc5536#section-3.1.3
        Self::write_header(buffer, "Message-ID", |buf| {
            buf.extend_from_slice(b"<");
            buf.extend_from_slice(self.message_id.as_bytes());
            buf.extend_from_slice(b">");
            Ok(())
        })?;

        // https://datatracker.ietf.org/doc/html/rfc5536#section-3.1.4
        Self::write_header(buffer, "Newsgroups", |buf| {
            let mut iter = self.newsgroups.iter();
            if let Some(group) = iter.next() {
                buf.extend_from_slice(group.as_bytes());
                for group in iter {
                    buf.extend_from_slice(b",");
                    buf.extend_from_slice(group.as_bytes());
                }
            }
            Ok(())
        })?;

        // https://datatracker.ietf.org/doc/html/rfc5536#section-3.1.5
        Self::write_header(buffer, "Path", |_| Ok(()))?;

        // https://datatracker.ietf.org/doc/html/rfc5536#section-3.1.6
        Self::write_header(buffer, "Subject", |buf| {
            buf.extend_from_slice(self.subject.as_bytes());
            Ok(())
        })?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn test_write_article_headers() {
        crate::util::init_tracing();

        let datetime = chrono::Utc
            .with_ymd_and_hms(2023, 3, 15, 12, 0, 42)
            .unwrap();

        let article_headers = ArticleHeaders {
            datetime,
            from: "userabc@def.ghi".to_string(),
            message_id: "randomid@jkl.mno".to_string(),
            newsgroups: vec!["test.group1".to_string(), "test.group2".to_string()],
            subject: "randomsubject@pqr.stu".to_string(),
        };

        let mut buffer = Vec::new();
        article_headers.write(&mut buffer).unwrap();
        let written = String::from_utf8(buffer).unwrap();

        let expected = "\
            Date: Wed, 15 Mar 2023 12:00:42 +0000\r\n\
            From: userabc@def.ghi\r\n\
            Message-ID: <randomid@jkl.mno>\r\n\
            Newsgroups: test.group1,test.group2\r\n\
            Path: \r\n\
            Subject: randomsubject@pqr.stu\r\n\
        ";

        assert_eq!(written, expected);
    }
}
