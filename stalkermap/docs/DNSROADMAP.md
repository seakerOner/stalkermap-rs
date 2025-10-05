# DNS RFC roadmap — quick checklist

 - Agnostic version:
   - Only parsing, encoding/decoding of DNS messages and helpers.
   - No dependency on an executor or transport; the user chooses.
   - Fast to implement, lightweight, ideal for advanced and custom usage.

 - Default version (std):
   - Implements blocking TCP/UDP transport using std::net.
   - Basic full functionality, easy to maintain.
   - Ideal for users who want simplicity and do not need async.

 - Tokio version (async):
   - Replaces blocking transport with tokio::net for async TCP/UDP.
   - Allows implementing RFC-inspired behaviors (TCP fallback, EDNS, retries, etc.) in a non-blocking way.
   - Can include opinionated helpers that speed up scanner development.

 Use this as the authoritative roadmap for implementing a robust DNS resolver
 (aimed at pentesting / network scanning use cases). Link targets point to the
 canonical RFC pages (rfc-editor / IETF datatracker) for reference.

 MUST (core behavior & compatibility)
 - RFC 1034 — Domain Names — Concepts and Facilities. 
   <https://www.rfc-editor.org/rfc/rfc1034.html>
   (Defines naming concepts and how DNS names are structured — foundation for everything.)

 - RFC 1035 — Domain Names — Implementation and Specification (message format, RRs, compression). 
   <https://www.rfc-editor.org/rfc/rfc1035.html>
   (DNS message wire format, resource record types, and name compression — essential parsing/encoding.)

 - RFC 2181 — Clarifications to the DNS Specification.
   <https://www.rfc-editor.org/rfc/rfc2181.html>
   (Important clarifications and operational guidance; read after 1034/1035.)

 - RFC 6891 — Extension Mechanisms for DNS (EDNS(0)).
   <https://www.rfc-editor.org/rfc/rfc6891.html>
   (Allows larger messages, new flags/options — required for modern queries and extensions.)

 - RFC 3596 — DNS Extensions to support IPv6 Address Records (AAAA).
   <https://www.rfc-editor.org/rfc/rfc3596.html>
   (Support for AAAA records — mandatory if you want IPv6 address lookups.)

 SHOULD (useful server features, transfers, and DNSSEC)
 - RFC 7766 — DNS Transport over TCP, TLS, and general transport guidance (implementation guidance).
   <https://www.rfc-editor.org/rfc/rfc7766.html>
   (How to handle TCP fallback, multiplexing guidance — important for robust resolvers/clients.)

 - RFC 5936 — DNS Zone Transfer Protocol (AXFR) and related zone transfer behavior.
   <https://www.rfc-editor.org/rfc/rfc5936.html>
   (Needed if you want to implement/handle zone transfers for enumeration or tooling that inspects zones.)

 - RFC 1995 — Incremental Zone Transfer (IXFR).
   <https://www.rfc-editor.org/rfc/rfc1995.html>
   (Optional for incremental transfers; relevant for full-featured zone handling tooling.)

 - RFC 2782 — DNS SRV Resource Records.
   <https://www.rfc-editor.org/rfc/rfc2782.html>
   (Service/port discovery records — useful for certain scanning workflows.)

 - DNSSEC family (validate authenticity / integrity of responses):
   - RFC 4033 — DNS Security Introduction and Requirements.
     <https://www.rfc-editor.org/rfc/rfc4033.html>
   - RFC 4034 — Resource Records for the DNS Security (DNSSEC) Protocol.
     <https://www.rfc-editor.org/rfc/rfc4034.html>
   - RFC 4035 — Protocol Modifications for DNS Security (DNSSEC).
     <https://www.rfc-editor.org/rfc/rfc4035.html>
   - RFC 5155 — DNSSEC NSEC3 (hashed authenticated denial of existence).
     <https://www.rfc-editor.org/rfc/rfc5155.html>
   - (Implement these if you need to validate responses cryptographically — highly recommended for security-focused tooling.)

 NICE-TO (privacy transports, mitigation, and newer RRs)
 - Privacy transports:
   - RFC 8484 — DNS over HTTPS (DoH).
     <https://www.rfc-editor.org/rfc/rfc8484.html>
   - RFC 7858 — DNS over TLS (DoT).
     <https://www.rfc-editor.org/rfc/rfc7858.html>
   - RFC 9250 — DNS over QUIC (DoQ).
     <https://www.rfc-editor.org/rfc/rfc9250.html>
   - (If you want privacy-preserving transport options for queries; useful for stealthy/modern tooling.)

 - RFC 7873 — DNS Cookies.
   <https://www.rfc-editor.org/rfc/rfc7873.html>
   (Simple anti-DoS protection useful for robust clients/servers.)

 - RFC 6698 — TLSA (DANE), RFC 8659 — CAA, SVCB/HTTPS drafts → IETF docs (HTTPS/SVCB RR).
   - TLSA (DANE): <https://www.rfc-editor.org/rfc/rfc6698.html>
   - CAA: <https://www.rfc-editor.org/rfc/rfc8659.html>
   - SVCB / HTTPS: see IETF datatracker/search for the latest draft → (links change while draft evolves).
   - (Specialized records that are useful for scanning modern services — implement if you want wide coverage.)

 - QNAME minimisation and related privacy best-practices (RFCs & drafts).
   <https://www.rfc-editor.org/search/rfc?q=qname+minimisation>
 - (Privacy guidance to avoid over-sharing query names to upstream servers — worth adopting for ethical scanning.)

 NOTES & IMPLEMENTATION STRATEGY
 - Start with RFC 1034 / 1035 / 2181 to cover message format, name rules and core behavior.
 - Add EDNS(0) (RFC 6891) early so your implementation can handle larger responses and modern flags.
 - Implement AAAA (RFC 3596) alongside A records to support IPv6 targets.
 - Implement transport handling (UDP + TCP per RFC 7766) — many servers require TCP fallback for larger results.
 - Add incremental features (AXFR/IXFR) and DNSSEC later as separate modules; keep wire encoding/decoding generic so features stack.
 - For privacy transports (DoH/DoT/DoQ) and SVCB/HTTPS: treat them as pluggable transports / optional features in your crate (feature flags).

 Further reading / authoritative sources:
 - RFC Editor (rfc-editor.org) — canonical RFC documents.
 - IETF Datatracker (datatracker.ietf.org) — drafts, working group pages, and status for SVCB/HTTPS and other evolving specs.
