//! The organisation (O) of CA certificates in PEM files, read directly (no openssl needed, any OS).
//! Matches what the Python scanner takes from `openssl x509 -subject`: the first O in the subject, cut at "," or "/".

/// Organisations of every certificate in a PEM text (in order; duplicates kept for the caller to merge).
pub fn subject_orgs(pem: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = pem;
    while let Some(start) = rest.find("-----BEGIN CERTIFICATE-----") {
        let body_start = start + "-----BEGIN CERTIFICATE-----".len();
        let Some(end) = rest[body_start..].find("-----END CERTIFICATE-----") else {
            break;
        };
        let b64: String = rest[body_start..body_start + end]
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        if let Some(org) = base64(&b64).as_deref().and_then(subject_org) {
            let cut = org.split([',', '/', '\n']).next().unwrap_or("").trim().to_string();
            if !cut.is_empty() {
                out.push(cut);
            }
        }
        rest = &rest[body_start + end..];
    }
    out
}

fn base64(s: &str) -> Option<Vec<u8>> {
    let val = |c: u8| -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => u32::from(c - b'A'),
            b'a'..=b'z' => u32::from(c - b'a' + 26),
            b'0'..=b'9' => u32::from(c - b'0' + 52),
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        })
    };
    let bytes: Vec<u8> = s.bytes().filter(|&c| c != b'=').collect();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        let mut n = 0u32;
        for (i, &c) in chunk.iter().enumerate() {
            n |= val(c)? << (18 - 6 * i);
        }
        let take = match chunk.len() {
            4 => 3,
            3 => 2,
            2 => 1,
            _ => 0,
        };
        out.extend_from_slice(&n.to_be_bytes()[1..=take]);
    }
    Some(out)
}

/// One DER element: (tag, content, rest).
fn tlv(d: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, d) = d.split_first()?;
    let (&first, mut d) = d.split_first()?;
    let len = if first < 0x80 {
        first as usize
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 4 || d.len() < n {
            return None;
        }
        let l = d[..n].iter().fold(0usize, |a, &b| (a << 8) | b as usize);
        d = &d[n..];
        l
    };
    if d.len() < len {
        return None;
    }
    Some((tag, &d[..len], &d[len..]))
}

/// organizationName (2.5.4.10) from the certificate's subject.
fn subject_org(der: &[u8]) -> Option<String> {
    let (_, cert, _) = tlv(der)?; // Certificate SEQUENCE
    let (_, tbs, _) = tlv(cert)?; // tbsCertificate SEQUENCE
    let mut fields = Vec::new();
    let mut rest = tbs;
    while !rest.is_empty() {
        let (tag, content, r) = tlv(rest)?;
        fields.push((tag, content));
        rest = r;
    }
    // [0] version (optional), serial, signature, issuer, validity, subject
    let skip = usize::from(fields.first().map(|f| f.0) == Some(0xa0));
    let (_, subject) = *fields.get(skip + 4)?;
    let mut rdns = subject;
    while !rdns.is_empty() {
        let (_, set, r) = tlv(rdns)?;
        rdns = r;
        let mut atvs = set;
        while !atvs.is_empty() {
            let (_, atv, r2) = tlv(atvs)?;
            atvs = r2;
            let (otag, oid, val) = tlv(atv)?;
            if otag == 0x06 && oid == [0x55, 0x04, 0x0a] {
                let (vtag, v, _) = tlv(val)?;
                return Some(match vtag {
                    0x1e => String::from_utf16_lossy(
                        &v.chunks(2)
                            .map(|c| u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]))
                            .collect::<Vec<_>>(),
                    ),
                    _ => String::from_utf8_lossy(v).to_string(),
                });
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// v3 certificate (has the [0] version field), subject O=Example Root, CN=v3.
    const V3: &str = "
-----BEGIN CERTIFICATE-----
MIIBUTCB+KADAgECAgkAqY9+0go7YgowCgYIKoZIzj0EAwIwJDEVMBMGA1UECgwM
RXhhbXBsZSBSb290MQswCQYDVQQDDAJ2MzAeFw0yNjExMTAwNDU4MTJaFw0zNjEx
MDcwNDU4MTJaMCQxFTATBgNVBAoMDEV4YW1wbGUgUm9vdDELMAkGA1UEAwwCdjMw
WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQ8inWOENm2t3iW5wUOcog2pdZ3HVsC
aATIxyKXKts7m3jlc3dNSUmSYPKea11UuvrY5YYPkVQC6V8IkyjT4iwSoxMwETAP
BgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0gAMEUCIGE04RK8z3QBx6fI1a8S
13CJgWfcMbj9yiQi7yfNNY0TAiEAw8BlIch5kwGwwdr/LxRvpbHZmauWzyk0IrgU
3bA+8gY=
-----END CERTIFICATE-----
";
    /// v1 certificate (no version field), subject C=US, O=Unit Test CA, Inc., CN=unit.
    const V1_COMMA: &str = "
-----BEGIN CERTIFICATE-----
MIICVzCCAfwCCQC/lbTk+apq2TAKBggqhkjOPQQDAjA5MQswCQYDVQQGEwJVUzEb
MBkGA1UECgwSVW5pdCBUZXN0IENBLCBJbmMuMQ0wCwYDVQQDDAR1bml0MB4XDTI2
MTExMDA0NTc1OFoXDTM2MTEwNzA0NTc1OFowOTELMAkGA1UEBhMCVVMxGzAZBgNV
BAoMElVuaXQgVGVzdCBDQSwgSW5jLjENMAsGA1UEAwwEdW5pdDCCAUswggEDBgcq
hkjOPQIBMIH3AgEBMCwGByqGSM49AQECIQD/////AAAAAQAAAAAAAAAAAAAAAP//
/////////////zBbBCD/////AAAAAQAAAAAAAAAAAAAAAP///////////////AQg
WsY12Ko6k+ez671VdpiGvGUdBrDMU7D2O848PifSYEsDFQDEnTYIhucEk2pmeOET
nSa3gZ9+kARBBGsX0fLhLEJH+Lzm5WOkQPJ3A32BLeszoPShOUXYmMKWT+NC4v4a
f5uO5+tKfA+eFivOM1drMV7Oy7ZAaDe/UfUCIQD/////AAAAAP//////////vOb6
racXnoTzucrC/GMlUQIBAQNCAAS56bhYRw5FpSv4BzokHmFBqevIOBi1SoGzHG/5
DeahgizLLWL6Iux/xiZnRcynSWW6mTYWYM0HAbr+2si9GwPhMAoGCCqGSM49BAMC
A0kAMEYCIQC+o9h1BEiYKtR4BkvcSrJnL2Lm7TWzJo+IJeElZ9+JhgIhAObiScsd
oDCjXNdnSWPSk334nsb2YOv0COyz1FhmX8MO
-----END CERTIFICATE-----
";
    /// A certificate whose subject has no O (CN=no-org only).
    const NO_ORG: &str = "
-----BEGIN CERTIFICATE-----
MIICBTCCAawCCQDZs8ksbhKujTAKBggqhkjOPQQDAjARMQ8wDQYDVQQDDAZuby1v
cmcwHhcNMjYxMTEwMDQ1NzU4WhcNMzYxMTA3MDQ1NzU4WjARMQ8wDQYDVQQDDAZu
by1vcmcwggFLMIIBAwYHKoZIzj0CATCB9wIBATAsBgcqhkjOPQEBAiEA/////wAA
AAEAAAAAAAAAAAAAAAD///////////////8wWwQg/////wAAAAEAAAAAAAAAAAAA
AAD///////////////wEIFrGNdiqOpPns+u9VXaYhrxlHQawzFOw9jvOPD4n0mBL
AxUAxJ02CIbnBJNqZnjhE50mt4GffpAEQQRrF9Hy4SxCR/i85uVjpEDydwN9gS3r
M6D0oTlF2JjClk/jQuL+Gn+bjufrSnwPnhYrzjNXazFezsu2QGg3v1H1AiEA////
/wAAAAD//////////7zm+q2nF56E87nKwvxjJVECAQEDQgAEcGAMzCH9lT4TjJ9p
Dz8DDlIsf8CBIpt/Z0L2MTtmArl4aiH2NHiZ1uipROq0qkDCQOFgiYfYroXiMSIQ
/TYLWzAKBggqhkjOPQQDAgNHADBEAiBYsHqah2qlPByDq+bFmyzC7a15Jdj05VGk
zk4vAuXL8gIgVsvLzIhWNSAzOnb0Vjfm/XvquljNpPr6HestYgNuteY=
-----END CERTIFICATE-----
";

    /// One DER element with a short or long-form length.
    fn der(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        let n = content.len();
        if n < 0x80 {
            out.push(u8::try_from(n).unwrap());
        } else {
            out.extend_from_slice(&[0x82, u8::try_from(n >> 8).unwrap(), u8::try_from(n & 0xff).unwrap()]);
        }
        out.extend_from_slice(content);
        out
    }

    /// A minimal certificate whose subject has one attribute: O as `value` with string tag `vtag`.
    fn cert_with_org(vtag: u8, value: &[u8]) -> Vec<u8> {
        let atv = der(0x30, &[der(0x06, &[0x55, 0x04, 0x0a]), der(vtag, value)].concat());
        let subject = der(0x30, &der(0x31, &atv));
        let empty = der(0x30, &[]);
        let tbs = [der(0x02, &[1]), empty.clone(), empty.clone(), empty, subject].concat();
        der(0x30, &der(0x30, &tbs))
    }

    fn pem(der_bytes: &[u8]) -> String {
        const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut b64 = String::new();
        for c in der_bytes.chunks(3) {
            let n = (u32::from(c[0]) << 16)
                | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
                | u32::from(*c.get(2).unwrap_or(&0));
            for i in 0..4 {
                if i <= c.len() {
                    b64.push(char::from(A[((n >> (18 - 6 * i)) & 63) as usize]));
                } else {
                    b64.push('=');
                }
            }
        }
        format!("-----BEGIN CERTIFICATE-----\n{b64}\n-----END CERTIFICATE-----\n")
    }

    #[test]
    fn reads_the_organisation_of_a_v3_certificate() {
        assert_eq!(subject_orgs(V3), vec!["Example Root"]);
    }

    #[test]
    fn reads_a_v1_certificate_and_cuts_at_a_comma_like_openssl_output() {
        assert_eq!(subject_orgs(V1_COMMA), vec!["Unit Test CA"]);
    }

    #[test]
    fn a_subject_without_an_organisation_gives_nothing() {
        assert_eq!(subject_orgs(NO_ORG), Vec::<String>::new());
    }

    #[test]
    fn every_certificate_in_a_bundle_in_order_with_text_around_them() {
        let bundle = format!("# a bundle\n{V1_COMMA}\nnot a cert\n{NO_ORG}{V3}{V3}");
        assert_eq!(
            subject_orgs(&bundle),
            vec!["Unit Test CA", "Example Root", "Example Root"]
        );
    }

    #[test]
    fn decodes_bmp_and_utf8_strings_and_cuts_at_a_slash() {
        let bmp: Vec<u8> = "Ünïcode CA".encode_utf16().flat_map(u16::to_be_bytes).collect();
        assert_eq!(subject_orgs(&pem(&cert_with_org(0x1e, &bmp))), vec!["Ünïcode CA"]);
        assert_eq!(
            subject_orgs(&pem(&cert_with_org(0x0c, "Acme/Ops".as_bytes()))),
            vec!["Acme"]
        );
        // an odd-length BMPString must not panic
        assert_eq!(subject_orgs(&pem(&cert_with_org(0x1e, &[0, 0x41, 0]))).len(), 1);
    }

    #[test]
    fn a_long_form_length_is_read() {
        let long = "L".repeat(300);
        assert_eq!(subject_orgs(&pem(&cert_with_org(0x0c, long.as_bytes()))), vec![long]);
    }

    #[test]
    fn broken_input_never_panics() {
        let good = cert_with_org(0x0c, b"Acme");
        // every truncation of a valid certificate
        for n in 0..good.len() {
            assert!(subject_orgs(&pem(&good[..n])).is_empty(), "truncated at {n}");
        }
        for bad in [
            "-----BEGIN CERTIFICATE-----\nnot*base64!\n-----END CERTIFICATE-----",
            "-----BEGIN CERTIFICATE-----\nMIIB",                    // no END
            "-----END CERTIFICATE----------BEGIN CERTIFICATE-----", // END before BEGIN
            "-----BEGIN CERTIFICATE----------END CERTIFICATE-----", // empty
            "",
        ] {
            assert!(subject_orgs(bad).is_empty(), "{bad}");
        }
        // lengths that claim more than there is, or 5+ length bytes
        assert!(tlv(&[0x30, 0x85, 1, 0, 0, 0, 0]).is_none());
        assert!(tlv(&[0x30, 0x84, 0xff, 0xff, 0xff, 0xff]).is_none());
        assert!(tlv(&[0x30, 0x80]).is_none());
        assert!(tlv(&[0x30, 0x05, 1, 2]).is_none());
    }

    #[test]
    fn tlv_splits_one_element() {
        assert_eq!(tlv(&[0x04, 2, 9, 8, 7]), Some((0x04, &[9u8, 8][..], &[7u8][..])));
        assert_eq!(tlv(&[0x04, 0x81, 1, 5]), Some((0x04, &[5u8][..], &[][..])));
    }

    #[test]
    fn base64_with_and_without_padding() {
        assert_eq!(base64("TWFu").as_deref(), Some(&b"Man"[..]));
        assert_eq!(base64("TWE=").as_deref(), Some(&b"Ma"[..]));
        assert_eq!(base64("TQ==").as_deref(), Some(&b"M"[..]));
        assert_eq!(base64("").as_deref(), Some(&b""[..]));
        assert_eq!(base64("TW!u"), None);
    }
}
