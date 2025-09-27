//! # Stalkermap DNS Resolver

#[derive(Debug)]
struct DnsMessage {
    header: HeaderSection,
    question: QuestionsSection,
    answer: AnswerSection,
    authority: AuthoritySection,
    additional: AdditionalSection,
}

#[derive(Debug)]
struct HeaderSection {
    id: u16,
    flags: u16,
    qd_count: u16,
    an_count: u16,
    ns_count: u16,
    ar_count: u16,
}

#[derive(Debug)]
struct QuestionsSection {
    name: String,
    record_type: u16,
    class: u16,
}

#[derive(Debug)]
struct AnswerSection {
    owner: String,
    record_type: u16,
    class: u16,
    ttl: u32,
    rd_length: u16,
    r_data: String,
}

#[derive(Debug)]
struct AuthoritySection {
    name: String,
    ty: u16,
    class: u16,
    ttl: u32,
    rd_length: u16,
    r_data: String,
}

#[derive(Debug)]
struct AdditionalSection {
    name: String,
    ty: u16,
    class: u16,
    ttl: u32,
    rd_length: u16,
    r_data: String,
}
