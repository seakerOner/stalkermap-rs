//! Stalkermap DNS Resolver

#[cfg(all(feature = "agnostic", any(feature = "std", feature = "tokio-dep")))]
compile_error!("Features `agnostic` and (`std`/`tokio`) cannot be enabled at the same time");

cfg_if::cfg_if! {
    if #[cfg(feature = "agnostic")] {
        pub mod agnostic;
        pub use self::agnostic::{
            AdditionalSection, AnswerSection, AuthoritySection, DnsHeaderFlags, DnsMessage, HeaderSection,
            OpCodeOptions, QuestionSection, RecordType, generate_id,
        };
    } else if #[cfg(any(feature = "std", feature = "tokio-dep"))] {
        mod standard;
        pub(crate) use self::standard::{
            AdditionalSection, AnswerSection, AuthoritySection, DnsHeaderFlags, DnsMessage, HeaderSection,
            OpCodeOptions, QuestionSection, RecordType,
        };
    }
}

pub mod transporter;

cfg_if::cfg_if! {
    if #[cfg( feature = "std" )]  {
        use std::net::UdpSocket;


        pub fn resolve_ipv4(name: &str) {
            let msg = DnsMessage::new_query(name, RecordType::A, OpCodeOptions::StandardQuery);

            let bytes = msg.encode_query();
        }
        pub fn resolve_ns(name: &str) {
            let msg = DnsMessage::new_query(name, RecordType::Ns, OpCodeOptions::StandardQuery);

            let bytes = msg.encode_query();
        }
        pub fn resolve_cname(name: &str) {
            let msg = DnsMessage::new_query(name, RecordType::Cname, OpCodeOptions::StandardQuery);

            let bytes = msg.encode_query();
        }
        pub fn resolve_soa(name: &str) {
            let msg = DnsMessage::new_query(name, RecordType::Soa, OpCodeOptions::StandardQuery);

            let bytes = msg.encode_query();
        }
        pub fn resolve_wks(name: &str) {
            let msg = DnsMessage::new_query(name, RecordType::Wks, OpCodeOptions::StandardQuery);

            let bytes = msg.encode_query();
        }
        pub fn resolve_ptr(name: &str) {
            let msg = DnsMessage::new_query(name, RecordType::Ptr, OpCodeOptions::StandardQuery);

            let bytes = msg.encode_query();
        }
        pub fn resolve_hinfo(name: &str) {
            let msg = DnsMessage::new_query(name, RecordType::Hinfo, OpCodeOptions::StandardQuery);

            let bytes = msg.encode_query();
        }
        pub fn resolve_minfo(name: &str) {
            let msg = DnsMessage::new_query(name, RecordType::Minfo, OpCodeOptions::StandardQuery);

            let bytes = msg.encode_query();
        }
        pub fn resolve_mx(name: &str) {
            let msg = DnsMessage::new_query(name, RecordType::Mx, OpCodeOptions::StandardQuery);

            let bytes = msg.encode_query();
        }
        pub fn resolve_txt(name: &str) {
            let msg = DnsMessage::new_query(name, RecordType::Txt, OpCodeOptions::StandardQuery);

            let bytes = msg.encode_query();
        }
    }
}
